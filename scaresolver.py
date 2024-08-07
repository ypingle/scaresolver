import SCA_api
import os
import zipfile
import argparse
import fnmatch
from packaging.version import parse as version_parse

def zip_folder(folder_to_zip, output_folder='src'):
    # Get the current working directory
    current_directory = os.getcwd()

    # Create the output folder if it doesn't exist
    output_folder_path = os.path.join(current_directory, output_folder)
    if not os.path.exists(output_folder_path):
        os.makedirs(output_folder_path)

    # Extract the folder name to use as the zip file name
    folder_name = os.path.basename(os.path.normpath(folder_to_zip))
    zip_file_name = folder_name + '.zip'
    zip_file_path = os.path.join(output_folder_path, zip_file_name)

# Define the patterns to include in the zip file
    patterns = ['package.json', '*.csproj', 'requirements.txt', 'pom.xml', 'composer.json']

    # Create the zip file
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_to_zip):
            for file in files:
                # Check if the file matches any of the patterns
                if any(fnmatch.fnmatch(file, pattern) for pattern in patterns):
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, folder_to_zip))

    return zip_file_path

#################################################
# main code
#################################################
def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="Process some parameters.")
    
    # Add the arguments
    parser.add_argument(
        '--src', 
        type=str, 
        help='A string value for source folder'
    )

    parser.add_argument(
        '--project_name', 
        type=str, 
        help='A string value for source folder'
    )

    # Parse the arguments
    args = parser.parse_args()
    # Accessing the arguments
    source_folder = args.src
    project_name = args.project_name

    print('source folder =' + source_folder)
    print('project name =' + project_name)

    zip_file_name = zip_folder(source_folder, 'src')

    if(zip_file_name != ""):
        # If zip file is generated, proceed with scanning
        SCA_api.SCA_scan_packages(project_name, zip_file_name)
 
if __name__ == '__main__':
   main()