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


def dbquery(thiscur, query):
    try:
        thiscur.execute(query)

        # display the PostgreSQL database server version
        print('SQL query returned {} rows'.format(thiscur.rowcount))

        res = thiscur.fetchall()

        return res

    # close the communication with the PostgreSQL
    except (Exception, psycopg2.DatabaseError) as error:
        print("Error:")
        print(error)


def close_conn(thisconn, thiscur):
    if thiscur is not None:
        thiscur.close()
    if thisconn is not None:
        thisconn.close()
        print('Database connection closed.')


def get_projdata(thiscur):
    res = dbquery(thiscur,
                  '''SELECT project.project_name, project_version.version_name, project_version.version_id,
                  project_version.distribution, 
                  project_version.phase, project.tier, component.component_id, component.component_name, 
                  component.component_version_id, component.component_version_name, component.security_critical_count, 
                  component.security_high_count, component.security_medium_count, 
                  component.security_low_count, component.security_ok_count, component.license_high_count, 
                  component.license_medium_count, component.license_low_count, component.license_ok_count,
                  component_license.license_display  
                  from component
                  Inner join project_version on component.project_version_id = project_version.version_id
                  Inner join component_license on component.id = component_license.component_table_id
                  Inner join project on project_version.project_id = project.project_id;''')

    thisdf = pd.DataFrame(res, columns=("projName", "projVerName", "projVerId", "projVerDist",
                                        "projVerPhase", "projTier", "compId", "compName",
                                        "compVerId", "compVerName",
                                        "secCritCount", "secHighCount", "secMedCount",
                                        "secLowCount", "secOkCount", "licHighCount",
                                        "licMedCount", "licLowCount", "licOkCount", "licName"))
    thisdf.fillna(value='', inplace=True)

    return thisdf


def get_vulndata(thiscur):
    res = dbquery(thiscur,
                  '''SELECT project_version.version_id, project.project_name, project_version.version_name, 
                  component.component_name, component.component_id, component.component_version_id,
                  component.component_version_name, vuln_id, related_vuln_id, vuln_source, 
                  case when severity_cvss3 is not null then severity_cvss3 else severity end,
                  case when temporal_score_cvss3 > 0 then temporal_score_cvss3
                       when base_score_cvss3 > 0 then base_score_cvss3
                       when temporal_score > 0 then temporal_score
                       when base_score > 0 then base_score end,
                  remediation_status, solution_available, 
                  workaround_available, TO_CHAR(published_on, 'YYYY/MM/DD') as published_on, 
                  component_vulnerability.description from component 
                  Inner join project_version on component.project_version_id = project_version.version_id 
                  Inner join component_vulnerability on component.id = component_vulnerability.component_table_id 
                  Inner join project on project_version.project_id = project.project_id;''')

    thisdf = pd.DataFrame(res, columns=("projVerId", "projName", "projVerName", "compName", "compId", "compVerId",
                                        "compVerName", "vulnId", "relatedVulnId", "vulnSource", "severity",
                                        "score", "remStatus", "solution", "workaround",
                                        "published_on", "desc"))
    thisdf.fillna(value='', inplace=True)
    return thisdf
