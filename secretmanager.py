import json
from nis import cat
import boto3
from botocore.exceptions import ClientError
import os
import csv
import pandas as pd
import json

sessions = {
    "medibuddy": boto3.session.Session(profile_name='medibuddy',region_name="ap-south-1"),
    "docsapp-prod": boto3.session.Session(profile_name='docsapp-prod',region_name="ap-south-1"),
    #"docsapptest": boto3.session.Session(profile_name='docsapptest',region_name="ap-south-1"),
    "docsapp": boto3.session.Session(profile_name='docsapp',region_name="ap-south-1")

}

session = boto3.session.Session(profile_name='medibuddy')

secs = []


def get_secret_names(session=session):
    secrets_client = session.client("secretsmanager")
    response = secrets_client.list_secrets()
    secs = []
    while True:
        for secret in response['SecretList']:
            secs.append(secret['Name'])
        # print(response['NextToken'])
        try:
            response = secrets_client.list_secrets(
                NextToken=response['NextToken'])
        except:
            break
    return secs


def get_secret_value(name, version=None, session=session):

    secrets_client = session.client("secretsmanager")
    kwargs = {"SecretId": name}
    if version is not None:
        kwargs["VersionStage"] = version
    response = secrets_client.get_secret_value(**kwargs)
    # print(response)
    return response


def create_secret(name, secret_value):

    print("Attempting to build : " + name)

    secrets_client = session.client("secretsmanager")
    kwargs = {"Name": name}
    if isinstance(secret_value, str):
        kwargs["SecretString"] = secret_value
    elif isinstance(secret_value, bytes):
        kwargs["SecretBinary"] = secret_value
    try:
        response = secrets_client.create_secret(**kwargs)
        print("Created Secret SuccessFully")
        return True
    except ClientError:
        print("Failed to create secret")
        return False


def update_secret_details(SecretId, SecretString):

    print("Attempting to updafe : " + SecretId)
    secrets_client = session.client("secretsmanager")
    try:
        res = secrets_client.put_secret_value(
            SecretId=SecretId, SecretString=SecretString
        )
        print("Updated Existing Secret SuccessFully")
        return True
    except ClientError:
        print("Failed to update secret")
        return False


def print_cred_declaration_step(cred_files, outputFile):

    for file in cred_files:
        # removing the .json at the end of the filename
        outputFile.writelines(
            [
                """def {filename} = "{filename}";""".format(
                    filename=file[: -5 or None]
                ),
                "\n",
            ]
        )


def print_secret_name_step(cred_files, outputFile):
    for file in cred_files:
        outputFile.writelines(
            [
                """def {filename}Secret = env+"_"+repoName+"_"+{filename};""".format(
                    filename=file[: -5 or None]
                ),
                "\n",
            ]
        )


def print_secret_filename_step(cred_files, outputFile):
    for file in cred_files:
        outputFile.writelines(
            [
                """def {filename}File = {filename};""".format(
                    filename=file[: -5 or None]
                ),
                "\n",
            ]
        )


def print_jenkins_building_step(cred_files, outputFile):
    for file in cred_files:

        outputFile.writelines(
            [
                """aws secretsmanager get-secret-value --secret-id ${{{secretname}}} | jq -rc .SecretString > config/credentials/${{{filename}}}.json""".format(
                    secretname=file[: -5 or None] + "Secret",
                    filename=file[: -5 or None] + "File",
                ),
                "\n",
            ]
        )


query_strings = [
"accesskey"
]
secs_df_list = []
for query in query_strings:
    secs_df_dict = {
        "secret_value" : query
    }
    for account in sessions.keys():
        session = sessions[account]
        secs = get_secret_names(session=session)
        secret_strings = {}
        sec_list = []
        for sec in secs:
            res = get_secret_value(sec, session=session)
            # print(res['SecretString'])
            if query in res['SecretString']:
                print(query + " Present in : " + str(sec) + " of account : " + account)
                sec_list.append(sec)
           



pd.DataFrame(secs_df_list).to_csv("secrets_found.csv", index=False)









