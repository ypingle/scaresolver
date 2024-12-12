import requests
import json
import os
import yaml
import smtplib
from email.mime.text import MIMEText

# Open the YAML file
with open('config_sca.yaml', 'r') as file:
    # Load the YAML contents
    config = yaml.safe_load(file)

SCA_account = config['SCA_account']
SCA_username = config['SCA_username']
SCA_password = config['SCA_password']
SCA_url = config['SCA_url']
SCA_api_url = config['SCA_api_url']
SCA_auth_url = config['SCA_auth_url']
SCA_proxy = config['SCA_proxy']
proxy_servers = {
   'https': SCA_proxy
}
SMTP_server = config['SMTP_server']
SMTP_port = config['SMTP_port']
SMTP_tls = config['SMTP_tls']
SMTP_user = config['SMTP_user']
SMTP_password = config['SMTP_password']
Email_from = config['Email_from']
Email_subject = config['Email_subject']
Email_body = config['Email_body']

# Function to send email
def send_email(sender, email_recipients, subject, body):
    recipients_list = email_recipients.split(',')  # Split the email_recipients string into individual email addresses
    recipients = [recipient.strip() for recipient in recipients_list]  # Remove leading/trailing spaces

    message = MIMEText(body)
    message['From'] = sender
    message['To'] = ", ".join(recipients)  # Join recipients list into a comma-separated string
    message['Subject'] = Email_subject

    try:
        smtp_obj = smtplib.SMTP(SMTP_server, SMTP_port)  
        if(SMTP_tls):
            smtp_obj.starttls()

        if(SMTP_user and SMTP_password):
            smtp_obj.login(SMTP_user, SMTP_password)  
        smtp_obj.sendmail(sender, recipients, message.as_string())  # Send email to all recipients
         
        smtp_obj.quit()
    except Exception as e:
        print("Exception: Failed to send email:", str(e))

def get_access_token():
    try:
        payload = {
            'username': SCA_username,
            'password': SCA_password,
            'acr_values': 'Tenant:' + SCA_account,
            'scope': 'sca_api',
            'client_id': 'sca_resource_owner',
            'grant_type': 'password'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(SCA_auth_url, headers=headers, data=payload, proxies=proxy_servers, verify=False)

#        print('get_access_token - token = ' + response.text)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        access_token = response.json()['access_token']
        return access_token
    except requests.RequestException as e:
        print("Exception: Failed to get access token:", str(e))
        return ""

def SCA_get_projects(access_token=""):
    if(not access_token):
        access_token = get_access_token()
    url = SCA_api_url + "/risk-management/projects"

    try:
        payload = {}
        headers = {
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        response_json = response.json()
    except Exception as e:
        print("Exception: SCA_get_project_latest_scan_id:", str(e))
        return ""
    else:
        try:
            return response_json
        except Exception as e:
            return ""

def SCA_get_project_latest_scan_id(project_name, access_token=""):
    if(not access_token):
        access_token = get_access_token()

    url = SCA_api_url + "/risk-management/projects?name=" + project_name

    try:
        payload = {}
        headers = {
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        response_json = response.json()
    except Exception as e:
        print("Exception: SCA_get_project_latest_scan_id:", str(e))
        return ""
    else:
        try:
            print('SCA_get_project_latest_scan_id scan_id= ' + response_json['latestScanId'])
            return response_json['latestScanId']
        except Exception as e:
            return ""
        
def SCA_create_project(project_name, access_token="", team_name=None):
    if(not access_token):
        access_token = get_access_token()
    url = SCA_api_url + "/risk-management/projects"

    try:
        payload = json.dumps({
        "name": project_name,
        "assignedTeams": [f"/CxServer/{team_name}"] if team_name else [],
        })
        headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("POST", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        project_id = response_json['id']  # Assuming the first project with the given name is returned
    except Exception as e:
        print("Exception: SCA_create_project:", str(e))
        return ""
    else:
        print('SCA_create_project - project_name= ' + response.text)
        return project_id
    
def SCA_get_project_id(project_name, access_token=""):
    if(not access_token):
        access_token = get_access_token()

    url = f"{SCA_api_url}/risk-management/projects?name={project_name}"

    try:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        project_id = response_json['id']  # Assuming the first project with the given name is returned
    except requests.RequestException as e:
        print("Exception: Failed to get project ID:", str(e))
        return ""
    except (KeyError, IndexError):
        print("Exception: Project ID not found")
        return ""
    else:
        print('SCA_get_project_id id:', project_id)
        return project_id

def SCA_get_upload_link(project_id, access_token):
    if(not access_token):
        access_token = get_access_token()
    
    url = f"{SCA_api_url}/api/uploads"

    try:
        payload = {
            "projectId": project_id
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.post(url, headers=headers, json=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        upload_url = response_json.get('url')
    except requests.RequestException as e:
        print("Exception: Failed to get upload link:", str(e))
        return ""
    except KeyError:
        print("Exception: 'uploadUrl' key not found in response")
        return ""
    else:
        print('SCA_get_upload_link - uploadUrl:', upload_url)
        return upload_url

def SCA_upload_file(upload_link, zip_file_path, access_token=""):
    if(not access_token):
        access_token = get_access_token()

    try:
        with open(zip_file_path, 'rb') as file:
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-zip-compressed',
                'Authorization': 'Bearer ' + access_token
            }
            response = requests.put(upload_link, headers=headers, data=file, proxies=proxy_servers, verify=False)
            response.raise_for_status()  # Raise an error for bad responses
            print('SCA_upload_file:', response.text)
    except requests.RequestException as e:
        print("Exception: Failed to upload file:", str(e))

def SCA_scan_zip(project_id, upload_file_url, access_token=""):
    if(not access_token):
        access_token = get_access_token()
    
    url = f"{SCA_api_url}/api/scans/uploaded-zip"

    try:
        payload = {
            "projectId": project_id,
            "uploadedFileUrl": upload_file_url
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.post(url, headers=headers, json=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        print('SCA_scan_zip scan_id:', response_json['scanId'])
        return response_json['scanId']
    except requests.RequestException as e:
        print("Exception: Failed to initiate scan:", str(e))
        return None
    except KeyError:
        print("Exception: 'scanId' key not found in response")
        return None

def SCA_get_scan_status(scan_id, access_token=""):
    if(not access_token):
        access_token = get_access_token()

    url = SCA_api_url + "/api/scans/" + scan_id
    
    try:
        payload = {}
        headers = {
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        status = response.content
   
    except Exception as e:
        print("Exception: SCA_get_scan_status", str(e))
        return ""
    else:
        print('SCSCA_get_scan_status')
        return status

def SCA_get_report(project_name, report_type, access_token=""):
    if(not access_token):
        access_token = get_access_token()

    scan_id = SCA_get_project_latest_scan_id(project_name, access_token)
    if scan_id:
        try:
            url = SCA_api_url + "/risk-management/risk-reports/" + scan_id + '/' + 'export?format=' + report_type + '&dataType[]=All'
        
            payload = {}
            headers = {
            'Authorization': 'Bearer ' + access_token
            }

            response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
            pdf_content = response.content
            if report_type.lower() == 'csv':
                report_path = os.getcwd() + '\\' + project_name + '_SCA_report.zip'
            else:    
                report_path = os.getcwd() + '\\' + project_name + '_SCA_report.' + report_type
            with open(report_path, 'wb') as f:
                f.write(pdf_content)
        except Exception as e:
            print("Exception: SCA_get_report", str(e))
            return ""
        else:
            print('SCA_get_report')
            return report_path
    else:
        return ""


def SCA_report_get_details_from_json(file_path):
    try:
        # Load JSON data from the file with explicit encoding
        with open(file_path, encoding='utf-8') as file:
            json_data = json.load(file)

        high_vulnerability_count = json_data['RiskReportSummary']['HighVulnerabilityCount']
        medium_vulnerability_count = json_data['RiskReportSummary']['MediumVulnerabilityCount']
        resultUrl = SCA_url + '/#/projects/' + json_data['RiskReportSummary']['ProjectId']

    except Exception as e:
        print("Exception: SCA_report_get_high_vulnerabilities_count failed:", str(e))
        return 0
    else:
        return resultUrl, high_vulnerability_count, medium_vulnerability_count

def SCA_scan_packages(project_name, zip_manifest_file, access_token=""):
    if(not access_token):
        access_token = get_access_token()

        project_id = SCA_get_project_id(access_token, project_name)
        if (project_id == ''):
            project_id = SCA_create_project(access_token, project_name)
        if project_id:
            upload_file_url = SCA_get_upload_link(access_token, project_id)
            if upload_file_url:
                SCA_upload_file(access_token, upload_file_url, zip_manifest_file)
                scan_id = SCA_scan_zip(access_token, project_id, upload_file_url)
                return scan_id
    return None
