# bddash
Black Duck Dash Analysis Console using data from a Black Duck Reporting DB

# Introduction

This is a plotly Dash app for viewing data from a [Black Duck](https://www.synopsys.com/software-integrity/security-testing/software-composition-analysis.html) server via the Reporting DB.

Data is read at startup either from the Reporting DB within a Black Duck server, or from JSON files created by a previous run if no connection is available or desired.

As a Plotly Dash application it can be run locally or hosted using a production server (see the deployment section below).

# Installation

Download and install the program as follows:

1. Download using `git clone https://github.com/matthewb66/bddash`
1. Install using `pip3 install -r requirements.txt`

# Configuration

The dashboard program can connect to the Black Duck Reporting DB to access data in the server or use JSON files. After connecting to the Reporting DB, the JSON files will be written to the dashboard host and can be used in offline mode subsequently.

1. Define how data will be obtained:
    1. Either create the conf/database.ini file with a connection to a Black Duck Reporting DB (see database.ini section below)
    1. Or ensure JSON data files exist in the data folder (db_projs.json, db_pols.json and db_vulns.json) without a conf/database.ini file
1. Create user credentials in the file conf/users.txt (see the section users.txt below)

## Reporting DB connection - conf/database.ini

The Black Duck Reporting DB is a PostgreSQL view accessed on port 54321 (on-premises deployments) or port 5432 (hosted servers).

An SQL connection config file `conf/database.ini` is required as follows:

    [database]
    server=
    user=

SSL certificates may be required to connect to the server, and these should be defined within the database.ini file.

For Synopsys-hosted Black Duck servers, you will also need to contact Support to open the Reporting DB ports and whitelist IP addresses which require connectivity, as well as obtain the certificates which must be configured in the database.ini file.

## Data from JSON files

If you have JSON files `db_projs.json`, `db_vulns.json` and `db_pols.json` extracted from a Reporting DB, ensure the files exist in the `data` sub-folder and remove the `database.ini` file to force the dashboard to read data from the files only.

## User configuration - conf/users.txt

The uses basic authentication; usernames and passwords are defined in the conf/users.txt as follows:

        {
             "user1": "password1"
        }

# Running the Dashboard

The dashboard program can be run on a workstation using python3 for debugging or single user access using the command:

        python3 app.py
        
Access the application via http://127.0.0.1:8888

# Deploying Production Server

Plotly Dash applications can be hosted on Dash Enterprise, on dedicated servers using app servers such as gunicorn or within hosting services such as Heroku - see https://dash.plotly.com/deployment.

Note that the dashboard has high memory requirements given the volume of data within a Black Duck server and the need to cache locally, and the free Heroku instances may report exhausted memory.

## Deploying using gunicorn

Gunicorn can be used as a Dash application server with the ability to support multi-user configurations via workers. Install the gunicorn prerequisies using:

       pip3 install gunicorn gevent
       
Start the gunicorn server with a defined number of workers (modify the IP and port as required):

       gunicorn --workers 2 --worker-class gevent --bind 127.0.0.1:8888 app:server
       
