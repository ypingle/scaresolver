import SCA_api
import os
import datetime
import argparse
import xml.etree.ElementTree as ET
import zipfile
import fnmatch

def SCA_scan_packages(project_name, zip_manifest_file, team_name=None):
    access_token = SCA_api.get_access_token()
    if access_token:
        project_id = SCA_api.SCA_get_project_id(project_name, access_token)
        if (project_id == ''):
            project_id = SCA_api.SCA_create_project(project_name, access_token, team_name)
        if project_id:
            upload_file_url = SCA_api.SCA_get_upload_link(project_id, access_token)
            if upload_file_url:
                SCA_api.SCA_upload_file(upload_file_url, zip_manifest_file, access_token)
                scan_id = SCA_api.SCA_scan_zip(project_id, upload_file_url, access_token)
                return scan_id
    return None

def convert_directory_packages_to_csproj(props_file_path, csproj_output_path):
    try:
        # Parse the Directory.Packages.props file
        tree = ET.parse(props_file_path)
        root = tree.getroot()

        # Create a list to store PackageReference elements
        package_references = []

        # Find all PackageVersion elements and create corresponding PackageReference elements
        for package_version in root.findall(".//PackageVersion"):
            package_id = package_version.get('Include')
            package_version_value = package_version.get('Version')

            # Create the PackageReference element for .csproj with the correct version
            package_ref = f"""
    <ItemGroup>
        <PackageReference Include="{package_id}" Version="{package_version_value}" />
    </ItemGroup>
            """
            package_references.append(package_ref)

        # Generate the .csproj content
        csproj_content = """
<Project Sdk="Microsoft.NET.Sdk">
    <PropertyGroup>
        <TargetFramework>netstandard2.0</TargetFramework>
    </PropertyGroup>
"""
        # Append all PackageReference elements
        csproj_content += "\n".join(package_references)
        
        # Close the Project tag
        csproj_content += "\n</Project>"

        # Write the content to the output .csproj file
        with open(csproj_output_path, 'w') as csproj_file:
            csproj_file.write(csproj_content)

        print(f"Successfully converted {props_file_path} to {csproj_output_path}")

    except ET.ParseError as e:
        print(f"XML parsing error in {props_file_path}: {e}")
    except Exception as e:
        print(f"Error converting {props_file_path} to {csproj_output_path}: {e}")

def validate_csproj_dependencies(csproj_path):
    """Verify that all PackageReference elements in the .csproj have a Version attribute."""
    try:
        tree = ET.parse(csproj_path)
        root = tree.getroot()

        # Check for PackageReference elements without a Version attribute
        for package_ref in root.findall(".//PackageReference"):
            if package_ref.get('Version') is None:
                return False
        return True

    except ET.ParseError as e:
        print(f"XML parsing error in {csproj_path}: {e}")
        return False
    except Exception as e:
        print(f"Error validating dependencies in {csproj_path}: {e}")
        return False

def zip_folder(folder_to_zip, project_name, output_folder='manifest'):
    try:
        # Determine if output_folder is a full path or relative to the current working directory
        if os.path.isabs(output_folder):
            output_folder_path = output_folder
        else:
            # Connect output_folder to the current working directory
            current_directory = os.getcwd()
            output_folder_path = os.path.join(current_directory, output_folder)

        # Create the output folder if it doesn't exist
        if not os.path.exists(output_folder_path):
            os.makedirs(output_folder_path)

        # Extract the folder name to use as the zip file name
        current_datetime = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        zip_file_name = f"{project_name}_{current_datetime}.zip"
        zip_file_path = os.path.join(output_folder_path, zip_file_name)

        # Define the patterns to include in the zip file
        patterns = ['package.json', 'packages.config', '*.csproj', 'requirements.txt', 'pom.xml', 'composer.json', 'Directory.Packages.props']

        converted_csproj = None

        # Create the zip file
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_to_zip):
                for file in files:
                    try:
                        # Check if the file matches any of the patterns
                        if any(fnmatch.fnmatch(file, pattern) for pattern in patterns):
                            file_path = os.path.join(root, file)

                            # Handle Directory.Packages.props by converting it to .csproj
                            if file == 'Directory.Packages.props':
                                converted_csproj = os.path.join(output_folder_path, 'converted.csproj')
                                convert_directory_packages_to_csproj(file_path, converted_csproj)

                                # Ensure the converted csproj is actually written to zip
                                if os.path.exists(converted_csproj):
                                    zipf.write(converted_csproj, 'converted.csproj')
                            
                            # Validate .csproj files to ensure all PackageReference elements have a Version attribute
                            elif fnmatch.fnmatch(file, '*.csproj'):
                                if validate_csproj_dependencies(file_path):
                                    zipf.write(file_path, os.path.relpath(file_path, folder_to_zip))
                                else:
                                    print(f"Excluding {file_path} from zip due to missing Version attributes in PackageReference.")

                            # Add other files directly to the zip
                            else:
                                zipf.write(file_path, os.path.relpath(file_path, folder_to_zip))

                    except Exception as e:
                        print(f"Error processing file {file} in zip creation: {e}")

            # If there was a conversion, clean up the temporary .csproj file
            if converted_csproj and os.path.exists(converted_csproj):
                os.remove(converted_csproj)

        print(f"Successfully created zip file: {zip_file_path}")
        return zip_file_path

    except Exception as e:
        print(f"Error zipping folder {folder_to_zip}: {e}")
        return None

def main():
    zip_file_name = None  # Initialize at the start to avoid UnboundLocalError
    try:
        parser = argparse.ArgumentParser(
            description="ScareSolver - Tool for scanning packages in a source folder"
        )
        parser.add_argument(
            "file_path", 
            help="The path to the source folder to scan."
        )
        parser.add_argument(
            "project_name", 
            help="The name of the project."
        )
        parser.add_argument(
            "--team_name", 
            default="", 
            help="Optional: The name of the team."
        )
        parser.add_argument(
            "--temp_folder", 
            default="", 
            help="Optional: The path of the temp folder to create zip."
        )
        parser.add_argument(
            "--offline", 
            action="store_true", 
            help="Run in offline mode. If set, no external connections will be made."
        )
        parser.add_argument(
            "--upload", 
            action="store_true", 
            help="Upload the scan results. If set, results will be uploaded."
        )

        args = parser.parse_args()

        source_folder = args.file_path
        project_name = args.project_name
        team_name = args.team_name
        offline = args.offline
        upload = args.upload
        temp_folder = args.temp_folder

        print(f"source folder = {source_folder}")
        print(f"project name = {project_name}")
        print(f"team name = {team_name}")
        print(f"offline mode = {offline}")
        print(f"upload results = {upload}")

        if offline:
            print("Running in offline mode. Skipping external dependencies.")
        if upload:
            if source_folder.endswith('.zip'):
                zip_file_name = source_folder
            else:
                raise ValueError("zip file path missing!")
        else:
            if(temp_folder):
                zip_file_name = zip_folder(source_folder, project_name, temp_folder)
            else:
                zip_file_name = zip_folder(source_folder, project_name)

        if zip_file_name and not offline:
            # If zip file is generated, proceed with scanning
            SCA_scan_packages(project_name, zip_file_name, team_name)

    except SystemExit as e:
        # Catch argparse errors (e.g., missing arguments)
        print(f"SystemExit: {e}. Check if required arguments are provided.")
    except Exception as e:
        print("Exception: upload_offline_files:", str(e))
    finally:
        # Delete the zip file after processing, but only if not offline
        if zip_file_name and os.path.exists(zip_file_name) and not offline:
            os.remove(zip_file_name)

if __name__ == '__main__':
    main()