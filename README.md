# bddash
Black Duck Dash Dashboard using Reporting DB

# Introduction

This is a plotly Dash app for viewing data from a [Black Duck](https://www.synopsys.com/software-integrity/security-testing/software-composition-analysis.html) server via the Reporting DB.

It caches the data in JSON files, and will only request new data every 60 minutes if connected to a server. Alternatively, it can be deployed offline using only the JSON data files in no connection is available or desired.

# Installation

Download and install the program as follows:

1. Download using `git clone https://github.com/matthewb66/bddash`
1. Install using `pip3 install -r requirements.txt`

# Configuration

The dashboard program can connect to the Black Duck Reporting DB to access data in the server or use JSON files. After connecting to the Reporting DB, the JSON files will be written to the dashboard host and used for rereading data, with a new connection every 60 minutes.

The Black Duck Reporting DB is a PostgreSQL view accessed on port 54321 (on-premises deployments) or port 5432 (hosted servers).

You will need to download the certificates for security, and create a config file `database.ini` as follows:

    [database]
    server=
    user=
    
For Synopsys-hosted Black Duck servers, you will also need to contact Support to open the Reporting DB ports and whitelist IP addresses which require connectivity, as well as obtain the certificates which must exist in the dashboard invocation folder.

If you have JSON files `db_projs.json` and `db_vulns.json` extracted from a Reporting DB, ensure the files exist in the invocation folder and remove the `database.ini` file to force the dashboard to read data from the files only.

# Deploying and Running the Dashboard

The dashboard program can be run on a workstation using python3 for debugging or single user access. However Plotly Dash applications can be hosted on Dash Enterprise, on dedicated servers using app servers such as gunicorn or within hosting services such as Heroku - see https://dash.plotly.com/deployment.

Note that the dashboard has high memory requirements given the volume of data within a Black Duck server and the need to cache locally, and the free Heroku instances may report exhausted memory.

