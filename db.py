import pandas as pd
import sys
import psycopg2
import psycopg2.extensions
from configparser import ConfigParser


def config(filename='database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db


def connect():
    """ Connect to the PostgreSQL database server """
    try:
        # read connection parameters
        params = config()

        # connect to the PostgreSQL server
        print('Connecting to the PostgreSQL database...')

        thisconn = psycopg2.connect(**params)
        thisconn.set_client_encoding('UNICODE')

        # create a cursor
        thiscur = thisconn.cursor()

        return thisconn, thiscur

    except (Exception, psycopg2.DatabaseError) as error:
        print("Error:")
        print(error)
        sys.exit(3)


# def dbquery(thiscur, query):
#     try:
#         thiscur.execute(query)
#
#         # display the PostgreSQL database server version
#         print('SQL query returned {} rows'.format(thiscur.rowcount))
#
#         res = thiscur.fetchall()
#
#         return res
#
#     # close the communication with the PostgreSQL
#     except (Exception, psycopg2.DatabaseError) as error:
#         print("Error:")
#         print(error)


def close_conn(thisconn, thiscur):
    if thiscur is not None:
        thiscur.close()
    if thisconn is not None:
        thisconn.close()
        print('Database connection closed.')


def get_projdata(thisconn):
    thisdf = pd.read_sql('''SELECT project.project_name as projname,
                  project_version.version_name as projvername, 
                  project_version.version_id as projverid,
                  project_version.distribution as projverdist, 
                  project_version.phase as projverphase, 
                  project.tier as projtier, 
                  component.component_id as compid, 
                  component.component_name as compname, 
                  component.component_version_id as compverid, 
                  component.component_version_name as compvername, 
                  component.security_critical_count as seccritcount, 
                  component.security_high_count as sechighcount, 
                  component.security_medium_count as secmedcount, 
                  component.security_low_count as seclowcount, 
                  component.security_ok_count as secokcount, 
                  component.license_high_count as lichighcount, 
                  component.license_medium_count as licmedcount, 
                  component.license_low_count as liclowcount, 
                  component.license_ok_count as licokcount,
                  component_license.license_display as licname
                  from component
                  Inner join project_version on component.project_version_id = project_version.version_id
                  Inner join component_license on component.id = component_license.component_table_id
                  Inner join project on project_version.project_id = project.project_id;''', con=thisconn)
    print('{} component rows returned'.format(thisdf.size))
    thisdf.fillna(value='', inplace=True)

    return thisdf


def get_vulndata(thisconn):
    thisdf = pd.read_sql('''SELECT project_version.version_id as projverid,
                  component.component_id as compid,
                  component.component_version_id as compverid,
                  component.component_name as compname,
                  component.component_version_name as compvername,
                  project_version.version_name as projvername,
                  project.project_name as projname,
                  vuln_id as vulnid, related_vuln_id as relatedvulnid, vuln_source as vulnsource, 
                  case when severity_cvss3 is not null then severity_cvss3 else severity end as severity,
                  case when temporal_score_cvss3 > 0 then temporal_score_cvss3
                       when base_score_cvss3 > 0 then base_score_cvss3
                       when temporal_score > 0 then temporal_score
                       when base_score > 0 then base_score end as score,
                  remediation_status as remstatus,
                  solution_available as solution, 
                  workaround_available as workaround,
                  TO_CHAR(published_on, 'YYYY/MM/DD') as pubdate, 
                  component_vulnerability.description as description, 
                  TO_CHAR(target_date, 'YYYY/MM/DD') as targetdate,
                  TO_CHAR(actual_date, 'YYYY/MM/DD') as actualdate,
                  comment as comment, attack_vector as attackvector, 
                  TO_CHAR(updated_on, 'YYYY/MM/DD') as updateddate
                  from component_vulnerability
                  Inner join component on component.id = component_vulnerability.component_table_id 
                  Inner join project_version on component.project_version_id = project_version.version_id 
                  Inner join project on project_version.project_id = project.project_id;''', con=thisconn)
    print('{} vulnerability rows returned'.format(thisdf.size))

    thisdf.fillna(value='', inplace=True)
    return thisdf


def get_poldata(thisconn):
    thisdf = pd.read_sql('''SELECT component_policies.project_version_id as projverid,
                 component.component_version_id as compverid,
                 policy_id as polid,
                 policy_name as polname,
                 policy_status as polstatus,
                 overridden_by as overrideby,
                 description as desc,
                 severity as polseverity
                 from component_policies
                 Inner join component on component.id = component_policies.component_table_id;''', con=thisconn)
    print('{} policy rows returned'.format(thisdf.size))
    thisdf.fillna(value='', inplace=True)
    return thisdf
