import dash
import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import dash_table
from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px
import json
import sys
import os
import psycopg2
import psycopg2.extensions
from time import time
import dash_auth
import re

from configparser import ConfigParser

if not os.path.isfile('users.txt'):
    print('No users.txt file - exiting')
    sys.exit(3)

with open('users.txt') as f:
    data = f.read()
VALID_USERNAME_PASSWORD_PAIRS = json.loads(data)
# VALID_USERNAME_PASSWORD_PAIRS = {
#     'user': 'password'
# }

app = dash.Dash(external_stylesheets=[dbc.themes.COSMO])
auth = dash_auth.BasicAuth(
    app,
    VALID_USERNAME_PASSWORD_PAIRS
)
server = app.server


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
        cur.close()
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
                  from component\n
                  Inner join project_version on component.project_version_id = project_version.version_id\n
                  Inner join component_license on component.id = component_license.component_table_id\n
                  Inner join project on project_version.project_id = project.project_id;''')

    thisdf = pd.DataFrame(res, columns=("projName", "projVerName", "projVerId", "projVerDist",
                                        "projVerPhase", "projTier", "compId", "compName",
                                        "compVerId", "compVerName",
                                        "secCritCount", "secHighCount", "secMedCount",
                                        "secLowCount", "secOkCount", "licHighCount",
                                        "licMedCount", "licLowCount", "licOkCount", "licName"))
    thisdf.fillna(value='', inplace=True)

    return thisdf


def proc_projdata(thisdf):
    newdf = thisdf
    newdf["All"] = "All"
    # Calculate total vulnerability count for all comps
    newdf = pd.DataFrame(newdf.eval('secAll = secCritCount + secHighCount + secMedCount + secLowCount'))

    # Sum columns for projVers
    sums = newdf.groupby("projVerId").sum().reset_index()
    # Remove duplicate component rows
    newdf.drop_duplicates(subset="projVerId", keep="first", inplace=True)
    # Count components in projvers
    df_counts = pd.DataFrame(thisdf['projVerId'].value_counts(ascending=False).
                             rename_axis('projVerId').reset_index(name='compCount'))

    # Merge compCount into df
    newdf = pd.merge(newdf, df_counts, on='projVerId')
    # Remove duplicate and unwanted columns before merge
    newdf.drop(['secAll', 'secCritCount', 'secHighCount', 'secMedCount', 'secLowCount', 'secOkCount', 'licHighCount',
                'licMedCount', 'licLowCount', 'licOkCount', 'compId', 'compName', 'compVerId', 'compVerName',
                'licName'], axis=1, inplace=True)
    # Merge sums into df
    newdf = pd.merge(newdf, sums, on='projVerId')
    print('{} Projects and {} Versions returned'.format(newdf.projName.nunique(), newdf.projVerId.nunique()))

    return newdf


def proc_comp_data(thisdf):
    # compdf will have 1 row per compver across all projvers
    # -  license risk will be the most severe across all projvers
    # projcompdf will have 1 row for each compver within each projver
    # - will map projVerId to compVerId

    compdf = thisdf

    # sort by license risk
    compdf = compdf.sort_values(by=['licHighCount', 'licMedCount', 'licLowCount'], ascending=False)
    # remove duplicates
    compdf = compdf.drop_duplicates(subset="compVerId", keep="first", inplace=False)

    def calc_license(row):
        if row['licHighCount'] > 0:
            return 'High'
        elif row['licMedCount'] > 0:
            return 'Medium'
        elif row['licLowCount'] > 0:
            return 'Low'
        elif row['licOkCount'] > 0:
            return 'OK'
        return ''

    # Calculate license risk value as licRisk
    compdf['licRisk'] = compdf.apply(calc_license, axis=1)
    compdf = compdf.drop(["projName", "projVerName", "projVerId", "projVerDist", "projVerPhase", "projTier"],
                         axis=1, inplace=False)

    compdf = compdf.sort_values(by=['compName'], ascending=True)

    # Calculate mapping of projvers to compvers
    projcompmapdf = thisdf

    projcompmapdf = projcompmapdf.drop(
        ["projName", "projVerName", "projVerDist", "projVerPhase", "projTier", "compId", "compName",
         "compVerName", "secCritCount", "secHighCount", "secMedCount", "secLowCount", "secOkCount",
         "licHighCount", "licMedCount", "licLowCount", "licOkCount", "licName", "All"],
        axis=1, inplace=False)

    projcompmapdf = projcompmapdf.sort_values(by=['projVerId', 'compVerId'], ascending=False)

    print('{} Components and {} Component Versions returned'.format(compdf.compName.nunique(),
                                                                    compdf.compVerId.nunique()))

    return compdf, projcompmapdf


def proc_licdata(thisdf):
    licnames = thisdf.licName.values
    compids = thisdf.compVerId.values
    # licrisks = thisdf.licRisk.values

    thislicmap_dict = {}  # Map of license names to compverids (dict of lists of compverids)
    # licrisk_dict = {}
    licname_list = []

    tempdf = thisdf
    sums = tempdf[~tempdf['licName'].str.startswith('(') &
                  ~tempdf['licName'].str.endswith(')')].groupby("licName").sum().reset_index()
    # print(sums.head(100).to_string())

    compindex = 0

    # def get_maxlicrisk(riskarray):
    #     for risk in ['High', 'Medium', 'Low', 'OK']:
    #         if risk in riskarray:
    #             return risk

    for lic in licnames:
        if lic in licname_list:
            compindex += 1
            continue
        licname_list.append(lic)
        splits = [lic]

        if lic[0] == '(' and lic[-1] == ')':
            lic = lic[1:-1]
            if ' AND ' in lic or ' OR ' in lic:
                splits = re.split(' OR | AND ', lic)

        for item in splits:
            # lics = thisdf[thisdf['licName'] == item].licRisk.unique()
            # maxrisk = get_maxlicrisk(lics)
            if item not in thislicmap_dict.keys():
                thislicmap_dict[item] = [compids[compindex]]
            elif compids[compindex] not in thislicmap_dict[item]:
                thislicmap_dict[item].append(compids[compindex])
            # licrisk_dict[item] = maxrisk
            # print(item, ' - ', maxrisk, ' - ', lic)

        compindex += 1

    # print(list(zip(licmap_dict.keys(), licrisk_dict.values())))
    print("{} Licenses returned".format(len(sums)))
    # temp_df = pd.DataFrame.from_records(list(zip(licmap_dict.keys(),
    #                                     licrisk_dict.values())), columns=['licName', 'licRisk'])
    # sorter = ['OK', 'Low', 'Medium', 'High']
    # temp_df.licRisk = temp_df.licRisk.astype("category")
    # temp_df.licRisk.cat.set_categories(sorter, inplace=True)
    return sums, thislicmap_dict


def get_vulndata(thiscur):
    res = dbquery(thiscur,
                  '''SELECT project_version.version_id, project.project_name, project_version.version_name, 
                  component.component_name, component.component_id, component.component_version_id,
                  component.component_version_name, vuln_id, related_vuln_id, vuln_source, severity_cvss3, 
                  temporal_score_cvss3, remediation_status, solution_available, 
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


def proc_vuln_data(thisdf):
    # vulndf will have 1 row per vulnId
    # projvulnmapdf will have 1 row for each vuln within each projver
    # - will map projVerId to compVerId

    vulndf = thisdf
    projvulnmapdf = thisdf
    compvulnmapdf = thisdf

    vulndf = vulndf.drop(["projVerId", "projName", "projVerName", "compName", "compId", "compVerId", "compVerName"],
                         axis=1, inplace=False)

    vulndf = vulndf.drop_duplicates(subset=["vulnId"], keep="first", inplace=False)
    vulndf = vulndf.sort_values(by=['score'], ascending=False)

    projvulnmapdf = projvulnmapdf.drop(["projName", "projVerName", "compName", "compId", "compVerId",
                                        "compVerName", "relatedVulnId", "vulnSource", "severity", "score",
                                        "remStatus", "solution", "workaround", "published_on", "desc"],
                                       axis=1, inplace=False)
    compvulnmapdf = compvulnmapdf.drop(["projVerId", "projName", "projVerName", "compName", "compId",
                                        "compVerName", "relatedVulnId", "vulnSource", "severity", "score",
                                        "remStatus", "solution", "workaround", "published_on", "desc"],
                                       axis=1, inplace=False)

    print('{} Vulnerabilities returned'.format(vulndf.vulnId.nunique()))

    return vulndf, projvulnmapdf, compvulnmapdf


def read_data_files():
    if not os.path.isfile('db_projs.json') or not os.path.isfile('db_vulns.json'):
        sys.exit(3)

    with open('db_projs.json') as jsonproj_file:
        dbprojdata = json.load(jsonproj_file)
    jsonproj_file.close()
    thisdfprojs = pd.read_json(dbprojdata, orient='split')
    with open('db_vulns.json') as jsonvuln_file:
        dbvulndata = json.load(jsonvuln_file)
    jsonvuln_file.close()
    thisdfvulns = pd.read_json(dbvulndata, orient='split')

    return thisdfprojs, thisdfvulns


def write_data_files():
    global df_main, df_vuln
    jsonout = df_main.to_json(orient="split")
    o = open("db_projs.json", "w")
    o.write(json.dumps(jsonout, indent=4))
    o.close()
    jsonout = df_vuln.to_json(orient="split")
    o = open("db_vulns.json", "w")
    o.write(json.dumps(jsonout, indent=4))
    o.close()


def create_projsummtab_fig_proj(thisdf, color_column):
    temp_df = thisdf.nlargest(200, 'compCount')
    thisfig = px.treemap(temp_df, path=['All', 'projName', 'projVerName'],
                         custom_data=['projName', 'projVerName', 'compCount'],
                         values='compCount',
                         color=color_column,
                         color_continuous_scale='Reds',
                         title='Project Versions (largest 200) - Size by Components ',
                         height=800)
    thisfig.update_traces(
        hovertemplate="<br>".join([
            "Project: %{customdata[0]}",
            "Version: %{customdata[1]}",
            "Components: %{customdata[2]}",
            # "Vulnerabilities: All %{customdata[3]}",
        ]),
    )

    return thisfig


def create_projsummtab_fig_compsec(thisdf):
    sec_labels = ['Critical', 'High', 'Medium', 'Low', 'OK']
    sec_names = ['Critical', 'High', 'Medium', 'Low', 'OK']

    # sec_values = [len(thisdf[thisdf['secCritCount'] > 0]), len(thisdf[thisdf['secHighCount'] > 0]),
    #                len(thisdf[thisdf['secMedCount'] > 0]), len(thisdf[thisdf['secLowCount'] > 0]),
    #                len(thisdf[thisdf['secOkCount'] > 0])]
    sec_values = [thisdf.secCritCount.sum(), thisdf.secHighCount.sum(), thisdf.secMedCount.sum(),
                  thisdf.secLowCount.sum(), thisdf.secOkCount.sum()]

    thisfig = px.pie(values=sec_values, labels=sec_labels, names=sec_names,
                     title='Component Security Risk',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(sort=False)
    return thisfig


def create_projsummtab_fig_complic(thisdf):
    lic_labels = ['High', 'Medium', 'Low', 'OK']
    lic_names = ['High', 'Medium', 'Low', 'None']
    # lic_values = [len(thisdf[thisdf['licHighCount'] > 0]), len(thisdf[thisdf['licMedCount'] > 0]),
    #               len(thisdf[thisdf['licLowCount'] > 0]), len(thisdf[thisdf['licOkCount'] > 0])]
    lic_values = [thisdf.licHighCount.sum(), thisdf.licMedCount.sum(), thisdf.licLowCount.sum(),
                  thisdf.licOkCount.sum()]

    thisfig = px.pie(values=lic_values, labels=lic_labels, names=lic_names, title='Component License Risk',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(sort=False)
    return thisfig


def create_projtab_table_projs(thisdf):
    # projName projVerName projVerId projVerDist projVerPhase projTier  All  compCount
    # secCritCount  secHighCount  secMedCount  secLowCount  secOkCount
    # licHighCount  licMedCount  licLowCount  licOkCount  secAll
    col_data = [
        {"name": ['', 'Project'], "id": "projName"},
        {"name": ['', 'Project Version'], "id": "projVerName"},
        {"name": ['', 'Components'], "id": "compCount"},
        {"name": ['Vulnerabilities', 'Crit'], "id": "secCritCount"},
        {"name": ['Vulnerabilities', 'High'], "id": "secHighCount"},
        {"name": ['Vulnerabilities', 'Medium'], "id": "secMedCount"},
        {"name": ['Vulnerabilities', 'Low'], "id": "secLowCount"},
        {"name": ['License Risk', 'High'], "id": "licHighCount"},
        {"name": ['License Risk', 'Medium'], "id": "licMedCount"},
        {"name": ['License Risk', 'Low'], "id": "licLowCount"},
        {"name": ['License Risk', 'None'], "id": "licOkCount"},
    ]
    df_temp = thisdf
    thistable = dash_table.DataTable(id='projtab_table_projs',
                                     columns=col_data,
                                     style_cell={
                                         'overflow': 'hidden',
                                         'textOverflow': 'ellipsis',
                                         'maxWidth': 0
                                     },
                                     data=df_temp.to_dict('records'),
                                     page_size=23, sort_action='native',
                                     row_selectable="single",
                                     cell_selectable=False,
                                     style_data_conditional=[
                                         {
                                             'if': {'column_id': 'projVerName'},
                                             'width': '160px'
                                         },
                                         {
                                             'if': {'column_id': 'compCount'},
                                             'width': '60px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secCritCount} > 0',
                                                 'column_id': 'secCritCount'
                                             },
                                             'backgroundColor': 'maroon',
                                             'color': 'white'
                                         },
                                         {
                                             'if': {'column_id': 'secCritCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secHighCount} > 0',
                                                 'column_id': 'secHighCount'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'secHighCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secMedCount} > 0',
                                                 'column_id': 'secMedCount'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'secMedCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secLowCount} > 0',
                                                 'column_id': 'secLowCount'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'secLowCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {'column_id': 'projName'},
                                             'width': '400px',
                                         },
                                         {
                                             'if': {'column_id': 'projVerName'},
                                             'width': '100px',
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licHighCount} > 0',
                                                 'column_id': 'licHighCount'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black',
                                         },
                                         {
                                             'if': {'column_id': 'licHighCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licMedCount} > 0',
                                                 'column_id': 'licMedCount'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black',
                                         },
                                         {
                                             'if': {'column_id': 'licMedCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licLowCount} > 0',
                                                 'column_id': 'licLowCount'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black',
                                         },
                                         {
                                             'if': {'column_id': 'licLowCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licOkCount} > 0',
                                                 'column_id': 'licOkCount'
                                             },
                                             'width': '50px',
                                         },
                                         {
                                             'if': {'column_id': 'licOkCount'},
                                             'width': '50px'
                                         },
                                     ],
                                     sort_by=[{'column_id': 'secCritCount', 'direction': 'desc'},
                                              {'column_id': 'secHighCount', 'direction': 'desc'},
                                              {'column_id': 'secMedCount', 'direction': 'desc'},
                                              {'column_id': 'secLowCount', 'direction': 'desc'}],
                                     merge_duplicate_headers=True
                                     )
    return thistable


def create_projtab_fig_subsummary(thisdf):
    df_temp = thisdf[["secCritCount", "secHighCount", "secMedCount", "secLowCount", "secOkCount"]].sum()
    sec_labels = ['Critical', 'High', 'Medium', 'Low']
    sec_names = ['Critical', 'High', 'Medium', 'Low']
    compsec_values = [df_temp.secCritCount.sum(), df_temp.secHighCount.sum(), df_temp.secMedCount.sum(),
                      df_temp.secLowCount.sum()]
    thisfig = px.pie(values=compsec_values, labels=sec_labels, names=sec_names,
                     title='Vulnerability Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_projtab_fig_subdetails(thisdf):
    lic_labels = ['High', 'Medium', 'Low', 'OK']
    lic_names = ['High', 'Medium', 'Low', 'None']
    complic_values = [thisdf.licHighCount.sum(), thisdf.licMedCount.sum(), thisdf.licLowCount.sum(),
                      thisdf.licOkCount.sum()]
    thisfig = px.pie(values=complic_values, labels=lic_labels, names=lic_names, title='License Risk Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_comptab_fig_compsec(thisdf):
    df_temp = thisdf[["secCritCount", "secHighCount", "secMedCount", "secLowCount", "secOkCount"]].sum()
    sec_labels = ['Critical', 'High', 'Medium', 'Low']
    sec_names = ['Critical', 'High', 'Medium', 'Low']
    compsec_values = [df_temp.secCritCount.sum(), df_temp.secHighCount.sum(), df_temp.secMedCount.sum(),
                      df_temp.secLowCount.sum()]
    thisfig = px.pie(values=compsec_values, labels=sec_labels, names=sec_names,
                     title='Vulnerability Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_comptab_fig_complic(thisdf):
    lic_labels = ['High', 'Medium', 'Low', 'OK']
    lic_names = ['High', 'Medium', 'Low', 'None']
    complic_values = [thisdf.licHighCount.sum(), thisdf.licMedCount.sum(), thisdf.licLowCount.sum(),
                      thisdf.licOkCount.sum()]
    thisfig = px.pie(values=complic_values, labels=lic_labels, names=lic_names, title='License Risk Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_comptab_table_compvers(thisdf):
    col_data = [
        {"name": ['', 'Component'], "id": "compName"},
        {"name": ['', 'Version'], "id": "compVerName"},
        {"name": ['Vulnerabilities', 'Crit'], "id": "secCritCount"},
        {"name": ['Vulnerabilities', 'High'], "id": "secHighCount"},
        {"name": ['Vulnerabilities', 'Medium'], "id": "secMedCount"},
        {"name": ['Vulnerabilities', 'Low'], "id": "secLowCount"},
        {"name": ['License', 'Risk'], "id": "licRisk"},
        {"name": ['License', 'Name'], "id": "licName"},
    ]
    df_temp = thisdf

    thistable = dash_table.DataTable(id='comptab_table_compvers',
                                     columns=col_data,
                                     style_cell={
                                         'overflow': 'hidden',
                                         'textOverflow': 'ellipsis',
                                         'maxWidth': 0
                                     },
                                     data=df_temp.to_dict('records'),
                                     row_selectable="single",
                                     page_size=20, sort_action='native',
                                     cell_selectable=False,
                                     style_data_conditional=[
                                         {
                                             'if': {
                                                 'filter_query': '{secCritCount} > 0',
                                                 'column_id': 'secCritCount'
                                             },
                                             'backgroundColor': 'maroon',
                                             'color': 'white'
                                         },
                                         {
                                             'if': {'column_id': 'secCritCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secHighCount} > 0',
                                                 'column_id': 'secHighCount'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'secHighCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secMedCount} > 0',
                                                 'column_id': 'secMedCount'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'secMedCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secLowCount} > 0',
                                                 'column_id': 'secLowCount'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'secLowCount'},
                                             'width': '50px'
                                         },
                                         {
                                             'if': {'column_id': 'licName'},
                                             'width': '300px',
                                             'overflow': 'hidden',
                                             'textOverflow': 'ellipsis',
                                         },
                                         {
                                             'if': {'column_id': 'compName'},
                                             'width': '400px',
                                         },
                                         {
                                             'if': {'column_id': 'compVerName'},
                                             'width': '100px',
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licRisk} = "High"',
                                                 'column_id': 'licRisk'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black',
                                             'width': '50px',
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licRisk} = "Medium"',
                                                 'column_id': 'licRisk'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black',
                                             'width': '50px',
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licRisk} = "Low"',
                                                 'column_id': 'licRisk'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black',
                                             'width': '50px',
                                         },

                                     ],
                                     sort_by=[{'column_id': 'secCritCount', 'direction': 'desc'},
                                              {'column_id': 'secHighCount', 'direction': 'desc'},
                                              {'column_id': 'secMedCount', 'direction': 'desc'},
                                              {'column_id': 'secLowCount', 'direction': 'desc'}],
                                     merge_duplicate_headers=True
                                     )
    return thistable


def create_vulntab_table_vulns(thisdf):
    # "projName", "projVerName", "compName", "compVerName", "vulnId", "relatedVulnId",
    # "vulnSource", "severity", "remStatus"))
    vuln_data = [
        {"name": ['Vuln Id'], "id": "vulnId"},
        {"name": ['Related Vuln'], "id": "relatedVulnId"},
        {"name": ['Severity'], "id": "severity"},
        {"name": ['CVSS3 Score'], "id": "score"},
        {"name": ['Remediation Status'], "id": "remStatus"},
        # {"name": ['Description'], "id": "desc"},
        {"name": ['Solution'], "id": "solution"},
        {"name": ['Workaround'], "id": "workaround"},
        # {"name": ['Comment'], "id": "comment"},
        {"name": ['Published Date'], "id": "published_on"},
    ]
    df_temp = thisdf
    df_temp = df_temp.sort_values(by=["score"], ascending=False)

    thistable = dash_table.DataTable(id='vulntab_table_vulns',
                                     columns=vuln_data,
                                     data=df_temp.to_dict('records'),
                                     page_size=20, sort_action='native',
                                     row_selectable="single",
                                     cell_selectable=False,
                                     style_data_conditional=[
                                         {
                                             'if': {
                                                 'filter_query': '{severity} = "CRITICAL"',
                                                 'column_id': 'severity'
                                             },
                                             'backgroundColor': 'maroon',
                                             'color': 'white'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{severity} = "HIGH"',
                                                 'column_id': 'severity'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{severity} = "MEDIUM"',
                                                 'column_id': 'severity'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{severity} = "LOW"',
                                                 'column_id': 'severity'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'severity'},
                                             'width': '80px'
                                         },
                                     ],
                                     sort_by=[{'column_id': 'score', 'direction': 'desc'}],
                                     merge_duplicate_headers=False
                                     )
    return thistable


def create_licab_table_lics(licdict):
    lic_cols = [
        {"name": ['License Name'], "id": "licName"},
        {"name": ['High Risk'], "id": "licHighCount"},
        {"name": ['Medium Risk'], "id": "licMedCount"},
        {"name": ['Low Risk'], "id": "licLowCount"},
    ]

    # columns = [{"name": i, "id": i} for i in df.columns],
    # [{'column-1': 4.5, 'column-2': 'montreal', 'column-3': 'canada'},
    #  {'column-1': 8, 'column-2': 'boston', 'column-3': 'america'}]

    thistable = dash_table.DataTable(id='lictab_table_lics',
                                     columns=lic_cols,
                                     data=licdict.to_dict('records'),
                                     page_size=20, sort_action='native',
                                     row_selectable="single",
                                     cell_selectable=False,
                                     style_data_conditional=[
                                         {
                                             'if': {
                                                 'filter_query': '{licHighCount} > 0',
                                                 'column_id': 'licHighCount'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licMedCount} > 0',
                                                 'column_id': 'licMedCount'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licLowCount} > 0',
                                                 'column_id': 'licLowCount'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'licHighCount'},
                                             'width': '120px'
                                         },
                                         {
                                             'if': {'column_id': 'licMedCount'},
                                             'width': '120px'
                                         },
                                         {
                                             'if': {'column_id': 'licLowCount'},
                                             'width': '120px'
                                         },
                                     ],
                                     sort_by=[{'column_id': 'licHighCount', 'direction': 'desc'},
                                              {'column_id': 'licMedCount', 'direction': 'desc'},
                                              {'column_id': 'licLowCount', 'direction': 'desc'}],
                                     merge_duplicate_headers=False
                                     )
    return thistable


def create_projtab_card_proj(projdata):
    global df_comp, df_projcompmap, df_proj
    # projName projVerName projVerId projVerDist projVerPhase projTier  All  compCount
    # secCritCount  secHighCount  secMedCount  secLowCount  secOkCount
    # licHighCount  licMedCount  licLowCount  licOkCount  secAll
    projname = ''
    projver = ''
    row1 = ''
    row2 = ''
    row3 = ''
    row4 = ''
    projusedbytitle = ''
    projstable = ''
    if projdata is not None:
        projname = projdata['projName'].values[0]
        projver = projdata['projVerName'].values[0]
        foundcomps = df_comp.loc[(df_comp['compName'] == projname) & (df_comp['compVerName'] == projver)]

        if foundcomps.shape[0] > 0:
            projlist = []
            projverlist = []
            for projids in df_projcompmap[df_projcompmap['compVerId'] == foundcomps.
                            compVerId.values[0]].projVerId.unique():
                projs = df_proj[df_proj['projVerId'] == projids]
                projlist.append(projs.projName.values[0])
                projverlist.append(projs.projVerName.values[0])

            projs_data = pd.DataFrame({
                "projName": projlist,
                "projVerName": projverlist
            })

            projusedbytitle = html.P('Used as sub-project in Projects:', className="card-text", )

            projusedin_cols = [
                {"name": ['Project'], "id": "projName"},
                {"name": ['Project Version'], "id": "projVerName"},
            ]
            projstable = dash_table.DataTable(
                columns=projusedin_cols,
                data=projs_data.to_dict('records'),
                page_size=6, sort_action='native',
                # row_selectable="single",
                # sort_by=[{'column_id': 'score', 'direction': 'desc'}],
                merge_duplicate_headers=False
            )

        row1 = html.Tr([html.Td("Distribution"), html.Td(projdata['projVerDist'])])
        row2 = html.Tr([html.Td("Tier"), html.Td(projdata['projTier'])])
        row3 = html.Tr([html.Td("Phase"), html.Td(projdata['projVerPhase'])])
        row4 = html.Tr([html.Td("Total Vulns"), html.Td(projdata['secAll'])])

    table_header = []

    table_body = [html.Tbody([row1, row2, row3, row4])]

    return dbc.Card(
        [
            dbc.CardHeader("Project Version Details"),
            dbc.CardBody(
                [
                    html.H4("Project: " + projname, className="card-title"),
                    html.H6("Project Version: " + projver, className="card-subtitle"),
                ],
            ),
            dbc.Table(table_header + table_body, bordered=True),
            projusedbytitle, projstable,
        ], id="projtab_card_proj",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "23rem"},
    )


def create_comptab_card_comp(compdata):
    global df_comp, df_projcompmap, df_proj

    compname = ''
    compver = ''
    projusedbytitle = ''
    projselbutton = ''
    projstable = ''
    if compdata is not None:
        compname = compdata['compName'].values[0]
        compver = compdata['compVerName'].values[0]
        compverid = compdata['compVerId'].values[0]

        projlist = []
        projverlist = []

        for projid in df_projcompmap[df_projcompmap['compVerId'] == compverid].projVerId.unique():
            projlist.append(df_proj[df_proj['projVerId'] == projid].projName.values[0])
            projverlist.append(df_proj[df_proj['projVerId'] == projid].projVerName.values[0])

        projs_data = pd.DataFrame({
            "projName": projlist,
            "projVerName": projverlist
        })

        projusedbytitle = html.P('Used in Projects:', className="card-text", )

        projusedin_cols = [
            {"name": ['Project'], "id": "projName"},
            {"name": ['Project Version'], "id": "projVerName"},
        ]

        projselbutton = html.Div(
            dbc.Button("Select Project", color="primary", className="mr-1", id="tabcomp_detail_selproj", size='sm'),
        )

        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            page_size=6, sort_action='native',
            row_selectable="single",
            merge_duplicate_headers=False
        )

    table_header = []
    table_body = []

    return dbc.Card(
        [
            # dbc.CardImg(src="/static/images/placeholder286x180.png", top=True),
            dbc.CardHeader("Project Version Details"),
            dbc.CardBody(
                [
                    html.H4("Component: " + compname, className="card-title"),
                    html.H6("Component Version: " + compver, className="card-subtitle"),
                ],
            ),
            dbc.Table(table_header + table_body, bordered=True),
            projusedbytitle, projstable, projselbutton,
        ], id="comptab_card_comp",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "23rem"},
    )


def create_vulntab_card_vuln(vulndata):
    global df_projvulnmap, df_compvulnmap, df_vuln, df_comp

    vulnid = ''
    vulnrelated = ''
    desc = ''

    usedbyprojstitle = ''
    usedbycompstitle = ''
    projstable = ''
    compstable = ''
    if vulndata is not None:
        vulnid = vulndata['vulnId'].values[0]
        vulnrelated = vulndata['relatedVulnId'].values[0]
        if vulnrelated == '':
            vulnrelated = 'None'
        desc = vulndata['desc'].values[0]

        projlist = []
        projverlist = []
        for projid in df_projvulnmap[df_projvulnmap['vulnId'] == vulnid].projVerId.unique():
            projlist.append(df_proj[df_proj['projVerId'] == projid].projName.values[0])
            projverlist.append(df_proj[df_proj['projVerId'] == projid].projVerName.values[0])
        usedbyprojstitle = html.P('Exposed in Projects:', className="card-text", )

        complist = []
        compverlist = []
        for compid in df_compvulnmap[df_compvulnmap['vulnId'] == vulnid].compVerId.unique():
            complist.append(df_comp[df_comp['compVerId'] == compid].compName.values[0])
            compverlist.append(df_comp[df_comp['compVerId'] == compid].compVerName.values[0])
        usedbycompstitle = html.P('Exposed in Components:', className="card-text", )

        projs_data = pd.DataFrame({
            "projName": projlist,
            "projVerName": projverlist
        })

        projusedin_cols = [
            {"name": ['Project'], "id": "projName"},
            {"name": ['Project Version'], "id": "projVerName"},
        ]
        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            page_size=4, sort_action='native',
            # row_selectable="single",
            merge_duplicate_headers=False
        )

        comps_data = pd.DataFrame({
            "compName": complist,
            "compVerName": compverlist
        })

        compusedin_cols = [
            {"name": ['Component'], "id": "compName"},
            {"name": ['Component Version'], "id": "compVerName"},
        ]
        compstable = dash_table.DataTable(
            columns=compusedin_cols,
            data=comps_data.to_dict('records'),
            page_size=4, sort_action='native',
            # row_selectable="single",
            # sort_by=[{'column_id': 'score', 'direction': 'desc'}],
            merge_duplicate_headers=False
        )

    return dbc.Card(
        [
            dbc.CardHeader("Vulnerability Details"),
            dbc.CardBody(
                [
                    html.H4("Vulnerability: " + vulnid, className="card-title"),
                    html.H6("Related to: " + vulnrelated, className="card-subtitle"),
                    # html.H6("Description: " , className="card-subtitle"),

                    html.P(desc),
                ],
            ),
            usedbyprojstitle, projstable,
            usedbycompstitle, compstable,
        ], id="vulntab_card_vuln",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "28rem"},
    )


def create_lictab_card_lic(licdata):
    global licmap_dict, df_comp, df_proj, df_projcompmap

    licname = ''

    usedbyprojstitle = ''
    usedbycompstitle = ''
    projstable = ''
    compstable = ''
    if licdata is not None:
        licname = licdata['licName'].values[0]

        complist = []
        compverlist = []
        projlist = []
        projverlist = []
        for compid in licmap_dict[licdata.licName.values[0]]:
            complist.append(df_comp[df_comp['compVerId'] == compid].compName.values[0])
            compverlist.append(df_comp[df_comp['compVerId'] == compid].compVerName.values[0])
            for projverid in df_projcompmap[df_projcompmap['compVerId'] == compid].projVerId.values:
                projlist.append(df_proj[df_proj['projVerId'] == projverid].projName.values[0])
                projverlist.append(df_proj[df_proj['projVerId'] == projverid].projVerName.values[0])

        usedbycompstitle = html.P('Exposed in Components:', className="card-text", )

        # for projid in df_projvulnmap[df_projvulnmap['vulnId'] == vulnid].projVerId.unique():
        #     projlist.append(df_proj[df_proj['projVerId'] == projid].projName.values[0])
        #     projverlist.append(df_proj[df_proj['projVerId'] == projid].projVerName.values[0])
        usedbyprojstitle = html.P('Exposed in Projects:', className="card-text", )

        projs_data = pd.DataFrame({
            "projName": projlist,
            "projVerName": projverlist
        })

        projusedin_cols = [
            {"name": ['Project'], "id": "projName"},
            {"name": ['Project Version'], "id": "projVerName"},
        ]
        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            page_size=5, sort_action='native',
            # row_selectable="single",
            merge_duplicate_headers=False
        )

        comps_data = pd.DataFrame({
            "compName": complist,
            "compVerName": compverlist
        })

        compusedin_cols = [
            {"name": ['Component'], "id": "compName"},
            {"name": ['Component Version'], "id": "compVerName"},
        ]
        compstable = dash_table.DataTable(
            columns=compusedin_cols,
            data=comps_data.to_dict('records'),
            page_size=5, sort_action='native',
            # row_selectable="single",
            # sort_by=[{'column_id': 'score', 'direction': 'desc'}],
            merge_duplicate_headers=False
        )

    return dbc.Card(
        [
            dbc.CardHeader("License Details"),
            dbc.CardBody(
                [
                    html.H4("License Name: " + licname, className="card-title"),
                    # html.H6("Related to: " + vulnrelated, className="card-subtitle"),
                    # html.H6("Description: " , className="card-subtitle"),

                    # html.P(desc),
                ],
            ),
            usedbyprojstitle, projstable,
            usedbycompstitle, compstable,
        ], id="lictab_card_lic",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "28rem"},
    )


df_main = None
df_vuln = None
lastdbreadtime = 0
readfrom = ''
if os.path.isfile('database.ini'):
    if lastdbreadtime:
        if (time() - lastdbreadtime) > 3600:
            # Read from DB
            readfrom = 'db'
        else:
            readfrom = 'file'
    else:
        readfrom = 'db'
        lastdbreadtime = time()
elif os.path.isfile('db_projs.json') and os.path.isfile('db_vulns.json'):
    readfrom = 'file'
else:
    print('\nNo database.ini or data files - exiting')
    sys.exit(3)

if readfrom == 'db':
    print('\nWill read data from DB connection')
    conn, cur = connect()
    print("Getting project data ...")
    df_main = get_projdata(cur)
    print("Getting vulnerability data ...")
    df_vuln = get_vulndata(cur)
    close_conn(conn, cur)
elif readfrom == 'file':
    print('\nWill read data from json files')
    df_main, df_vuln = read_data_files()

if df_main is None or df_main.size == 0:
    print("No data obtained from DB or files")
    sys.exit(2)

if readfrom == 'db':
    print("Writing data to JSON files ...")
    write_data_files()

df_proj = proc_projdata(df_main)
df_comp, df_projcompmap = proc_comp_data(df_main)
df_vuln, df_projvulnmap, df_compvulnmap = proc_vuln_data(df_vuln)
df_lic, licmap_dict = proc_licdata(df_comp)

print("READY\n")

def create_projsummtab(df_proj, color_col):
    return dbc.Row([
            dbc.Col([
                dbc.Row(
                    dbc.Col(
                        dcc.Graph(id='projsummtab_graph_proj', figure=create_projsummtab_fig_proj(df_proj, color_col)),
                    ),
                ),
                dbc.Row([
                    dbc.Col(
                        html.Div(children="Select Colour Scheme"), width=2
                    ),
                    dbc.Col(
                        dbc.RadioItems(
                            options=[
                                {'label': 'Critical Vulns', 'value': 'secCritCount'},
                                {'label': 'High Vulns', 'value': 'secHighCount'},
                                {'label': 'High Licenses', 'value': 'licHighCount'},
                            ],
                            id='summtab_radio',
                            value='secCritCount',
                            inline=True,
                            # labelStyle={'display': 'inline-block'}
                        ), width=5
                    )], justify='end'
                ),
            ], width=8),
            dbc.Col([
                dcc.Graph(id='projsummtab_graph_compsec', figure=create_projsummtab_fig_compsec(df_proj)),
                dcc.Graph(id='projsummtab_graph_complic', figure=create_projsummtab_fig_complic(df_proj)),
            ], width=4),
        ])


def create_projtab(df_proj):
    return dbc.Row([
        dbc.Col(create_projtab_table_projs(df_proj), width=9),
        dbc.Col(
            dbc.Tabs(
                [
                    dbc.Tab(
                        [
                            dcc.Graph(id='projtab_graph_compsec',
                                      figure=create_projtab_fig_subsummary(df_proj)),
                            dcc.Graph(id='projtab_graph_complic',
                                      figure=create_projtab_fig_subdetails(df_proj)),
                        ], label='Projects Summary',
                        tab_id="tab_proj_subsummary", id="tab_proj_subsummary",
                    ),
                    dbc.Tab(
                        create_projtab_card_proj(None),
                        label='Selected Project',
                        tab_id="tab_proj_subdetail", id="tab_proj_subdetail",
                    )
                ], id="tabs_proj_subtabs",
            ), width=3
        ),
    ])


def create_comptab(df_comp):
    return dbc.Row(
        [
            dbc.Col([
                create_comptab_table_compvers(df_comp),
                # html.Div(children="Component Search"),
                # dbc.Input(id="comptab_input_comp", placeholder="", type="text"),
            ], width=8),
            dbc.Col(
                dbc.Tabs(
                    [
                        dbc.Tab(
                            [
                                dcc.Graph(id='comptab_graph_compsec', figure=create_comptab_fig_compsec(df_comp)),
                                dcc.Graph(id='comptab_graph_complic', figure=create_comptab_fig_complic(df_comp)),
                            ], label='Components Summary',
                            tab_id="tab_comp_subsummary", id="tab_comp_subsummary",
                        ),
                        dbc.Tab(
                            create_comptab_card_comp(None),
                            label='Selected Component',
                            tab_id="tab_comp_subdetail", id="tab_comp_subdetail",
                        ),
                    ]
                ), width=4
            ),
        ]
    )


def create_vulntab(df_vuln):
    return dbc.Row(
        [
            dbc.Col(create_vulntab_table_vulns(df_vuln), width=8),
            dbc.Col(create_vulntab_card_vuln(None), width=4, id='col_vulntab_vuln'),
        ]
    )


def create_lictab(df_lic):
    return dbc.Row(
        [
            dbc.Col(create_licab_table_lics(df_lic), width=7),
            dbc.Col(create_lictab_card_lic(None), width=5,
                    id='col_lictab_lic'),
        ]
    )


app.layout = dbc.Container(
    [
        # 		dcc.Store(id='sec_values', storage_type='local'),
        # 		dcc.Store(id='lic_values', storage_type='local'),
        dbc.NavbarSimple(
            children=[
                dbc.NavItem(dbc.NavLink("Documentation", href="#")),
            ],
            brand="Black Duck Dashboard",
            brand_href="#",
            color="primary",
            dark=True,
            fluid=True,
        ),
        dbc.Row(
            [
                dbc.Col(html.Div(children="Projects"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_projects",
                        options=[
                            {'label': i, 'value': i} for i in df_main.sort_values(by=['projName'], ascending=True).
                                projName.unique()
                        ], multi=True, placeholder='Select Projects ...'
                    ), width=5
                ),
                dbc.Col(html.Div(children="Versions"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_versions",
                        options=[], multi=True, placeholder='Select Versions ...'
                    ), width=5
                ),
            ]
        ),
        dbc.Row(
            [
                dbc.Col(html.Div(children="Tiers"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_tiers",
                        options=[
                            {'label': i, 'value': i} for i in df_main.projTier.unique()
                        ],
                        multi=True
                    ), width=3
                ),
                dbc.Col(html.Div(children="Distribution"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_dists",
                        options=[
                            {'label': i, 'value': i} for i in df_main.projVerDist.unique()
                        ],
                        multi=True
                    ), width=3
                ),
                dbc.Col(html.Div(children="Phase"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_phases",
                        options=[
                            {'label': i, 'value': i} for i in df_main.projVerPhase.unique()
                        ],
                        multi=True
                    ), width=3
                ),
                dbc.Col(html.Div(children="Security Risk"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_secrisk",
                        options=[
                            {'label': 'Critical', 'value': 'Critical'},
                            {'label': 'High', 'value': 'High'},
                            {'label': 'Medium', 'value': 'Medium'},
                            {'label': 'Low', 'value': 'Low'},
                        ],
                        multi=True
                    ), width=3
                ),
                dbc.Col(html.Div(children="License Risk"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_licrisk",
                        options=[
                            {'label': 'High', 'value': 'High'},
                            {'label': 'Medium', 'value': 'Medium'},
                            {'label': 'Low', 'value': 'Low'},
                        ],
                        multi=True
                    ), width=3
                ),
                dbc.Col(html.Div(children="Components"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_comps",
                        options=[
                            {'label': i, 'value': i} for i in df_comp.sort_values(by=['compName'], ascending=True).
                                compName.unique()
                        ],
                        multi=True
                    ), width=3
                )
            ]
        ),
        dbc.Row(html.Hr()),
        dbc.Row(
            dbc.Col(
                dbc.Spinner(dbc.Tabs(
                    [
                        dbc.Tab(  # SUMMARY TAB
                            create_projsummtab(df_proj, 'secCritCount'), label="Projects Summary",
                            tab_id="tab_projsummary", id="tab_projsummary",
                        ),
                        dbc.Tab(  # PROJECTS TAB
                            create_projtab(df_proj),
                            label="Projects (" + str(df_proj.projName.nunique()) + ") & Versions (" +
                                  str(df_proj.projVerId.nunique()) + ")",
                            tab_id="tab_projects", id="tab_projects"
                        ),
                        dbc.Tab(  # COMPONENTS TAB
                            create_comptab(df_comp),
                            label="Components (" + str(df_main.compName.nunique()) + ")",
                            tab_id="tab_components", id="tab_components"
                        ),
                        dbc.Tab(  # VULNS TAB
                            create_vulntab(df_vuln),
                            label="Vulnerabilties (" + str(df_vuln.vulnId.nunique()) + ")",
                            tab_id="tab_vulns", id="tab_vulns"
                        ),
                        dbc.Tab(  # LICENSE TAB
                            create_lictab(df_lic),
                            label="Licenses (" + str(df_lic.licName.nunique()) + ")",
                            tab_id="tab_lics", id="tab_lics"
                        )
                    ],
                    id="tabs",
                    active_tab="tab_projsummary",
                ), id='spinner_main',),
                width=12
            )
        ),
    ], fluid=True
)


@app.callback(
    Output('col_vulntab_vuln', 'children'),
    [
        Input('vulntab_table_vulns', 'derived_virtual_data'),
        Input('vulntab_table_vulns', 'derived_virtual_selected_rows'),
    ]
)
def get_active_cell_vuln(vulndata, rows):
    global df_vuln
    if rows:
        return create_vulntab_card_vuln(df_vuln[df_vuln['vulnId'] == vulndata[rows[0]]['vulnId']])

    return create_vulntab_card_vuln(None)


@app.callback(
    Output('col_lictab_lic', 'children'),
    [
        Input('lictab_table_lics', 'derived_virtual_data'),
        Input('lictab_table_lics', 'derived_virtual_selected_rows'),
    ]
)
def get_active_cell_lic(licdata, rows):
    global df_lic
    if rows:
        # print(licdata)
        # print(rows)
        return create_lictab_card_lic(df_lic[df_lic['licName'] == licdata[rows[0]]['licName']])

    return create_lictab_card_lic(None)


@app.callback(
    Output('tab_comp_subdetail', 'children'),
    # State('vulntab_table_vulns', 'data')
    [
        Input('comptab_table_compvers', 'derived_virtual_data'),
        Input('comptab_table_compvers', 'derived_virtual_selected_rows'),
    ]
)
def get_active_cell_comp(data, rows):
    global df_comp
    if rows:
        # print(active_cell)
        return create_comptab_card_comp(df_comp[df_comp['compVerId'] == data[rows[0]]['compVerId']])

    return create_comptab_card_comp(None)


@app.callback(
    Output('tab_proj_subdetail', 'children'),
    [
        Input('projtab_table_projs', 'derived_virtual_data'),
        Input('projtab_table_projs', 'derived_virtual_selected_rows'),
    ]

)
def get_active_cell_proj(data, rows):
    global df_proj
    if rows:
        return create_projtab_card_proj(df_proj[df_proj['projVerId'] == data[rows[0]]['projVerId']])

    return create_projtab_card_proj(None)


# Update graphs and select options based on selection inputs
@app.callback(
    [
        Output('tab_projsummary', 'children'),
        Output('tab_projects', 'children'),
        Output('tab_components', 'children'),
        Output("tab_vulns", "children"),
        Output("sel_versions", 'options'),
        Output("sel_tiers", 'options'),
        Output("sel_dists", 'options'),
        Output("sel_phases", 'options'),
        Output('sel_comps', 'options'),
        Output('spinner_main', 'children'),
    ], [
        Input('sel_projects', 'value'),
        Input('sel_versions', 'value'),
        Input('sel_tiers', 'value'),
        Input('sel_dists', 'value'),
        Input('sel_phases', 'value'),
        Input('sel_secrisk', 'value'),
        Input('sel_licrisk', 'value'),
        Input('sel_comps', 'value'),
        # Input('projsummtab_graph_proj', 'clickData'),
        # Input('comptab_input_comp', 'value'),
        Input('summtab_radio', 'value'),
    ]
)
def mycallback(projs, vers, tiers, dists, phases, secrisk, licrisk, comps, proj_radio):
    global df_proj
    global df_comp, df_projcompmap
    global df_vuln, df_projvulnmap, df_compvulnmap

    ctx = dash.callback_context

    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    temp_df_proj = df_proj
    temp_df_comp = df_comp
    temp_df_vuln = df_vuln
    recalc = False

    # Process existing select dropdowns
    if projs is not None and len(projs) > 0:
        # Filter projects from selection
        temp_df_proj = temp_df_proj[temp_df_proj.projName.isin(projs)]
        # Filter components based on projcompmap

        # Set project version dropdowns
        sel_vers_options = [{'label': i, 'value': i} for i in temp_df_proj.projVerName.unique()]
        recalc = True
    else:
        # Version selection only possible if Project selected
        sel_vers_options = []

    if vers is not None and len(vers) > 0:
        # Filter versions from selection
        temp_df_proj = temp_df_proj[temp_df_proj.projVerName.isin(vers)]
        recalc = True

    if comps is not None and len(comps) > 0:
        # Filter projects based on phase selection

        temp_df_comp = temp_df_comp[temp_df_comp.compName.isin(comps)]

        compverids = temp_df_comp['compVerId'].unique()
        projverids = df_projcompmap[df_projcompmap.compVerId.isin(compverids)]['projVerId'].unique()
        temp_df_proj = temp_df_proj[temp_df_proj.projVerId.isin(projverids)]

        vulnids = df_compvulnmap[df_compvulnmap.compVerId.isin(compverids)]['vulnId'].unique()
        temp_df_vuln = temp_df_vuln[temp_df_vuln.vulnId.isin(vulnids)]
        recalc = True

    # Modify dropdown options
    sel_tiers_options = [{'label': i, 'value': i} for i in temp_df_proj.projTier.unique()]
    sel_dists_options = [{'label': i, 'value': i} for i in temp_df_proj.projVerDist.unique()]
    sel_phases_options = [{'label': i, 'value': i} for i in temp_df_proj.projVerPhase.unique()]
    sel_comps_options = [{'label': i, 'value': i} for i in temp_df_comp.compName.sort_values().unique()]

    if tiers is not None and len(tiers) > 0:
        # Filter projects based on tier selection
        temp_df_proj = temp_df_proj[temp_df_proj.projTier.isin(tiers)]
        recalc = True
    if dists is not None and len(dists) > 0:
        # Filter projects based on distribution selection
        temp_df_proj = temp_df_proj[temp_df_proj.projVerDist.isin(dists)]
        recalc = True
    if phases is not None and len(phases) > 0:
        # Filter projects based on phase selection
        temp_df_proj = temp_df_proj[temp_df_proj.projVerPhase.isin(phases)]
        recalc = True

    if recalc:
        # Filter components based on projcompmap
        projverids = temp_df_proj['projVerId'].unique()

        compverids = df_projcompmap[df_projcompmap.projVerId.isin(projverids)]['compVerId'].unique()

        temp_df_comp = temp_df_comp[temp_df_comp.compVerId.isin(compverids)]

        # Filter vulns based on projvulnmap
        vulnids = df_projvulnmap[df_projvulnmap.projVerId.isin(projverids)]['vulnId'].unique()
        temp_df_vuln = temp_df_vuln[temp_df_vuln.vulnId.isin(vulnids)]

    if secrisk is not None and len(secrisk) > 0:
        # Filter projects based on security risk selection
        if 'Critical' in secrisk:
            temp_df_proj = temp_df_proj[temp_df_proj.secCritCount > 0]
            temp_df_comp = temp_df_comp[temp_df_comp.secCritCount > 0]
            temp_df_vuln = temp_df_vuln[temp_df_vuln.severity == 'CRITICAL']
        if 'High' in secrisk:
            temp_df_proj = temp_df_proj[temp_df_proj.secHighCount > 0]
            temp_df_comp = temp_df_comp[temp_df_comp.secHighCount > 0]
            temp_df_vuln = temp_df_vuln[temp_df_vuln.severity == 'HIGH']
        if 'Medium' in secrisk:
            temp_df_proj = temp_df_proj[temp_df_proj.secMedCount > 0]
            temp_df_comp = temp_df_comp[temp_df_comp.secMedCount > 0]
            temp_df_vuln = temp_df_vuln[temp_df_vuln.severity == 'MEDIUM']
        if 'Low' in secrisk:
            temp_df_proj = temp_df_proj[temp_df_proj.secLowCount > 0]
            temp_df_comp = temp_df_comp[temp_df_comp.secLowCount > 0]
            temp_df_vuln = temp_df_vuln[temp_df_vuln.severity == 'LOW']

    if licrisk is not None and len(licrisk) > 0:
        # Filter projects based on security risk selection
        if 'High' in licrisk:
            temp_df_proj = temp_df_proj[temp_df_proj.licHighCount > 0]
            temp_df_comp = temp_df_comp[temp_df_comp.licHighCount > 0]

        if 'Medium' in licrisk:
            temp_df_proj = temp_df_proj[temp_df_proj.licMedCount > 0]
            temp_df_comp = temp_df_comp[temp_df_comp.licMedCount > 0]

        if 'Low' in licrisk:
            temp_df_proj = temp_df_proj[temp_df_proj.licLowCount > 0]
            temp_df_comp = temp_df_comp[temp_df_comp.licLowCount > 0]

    # projtab_label = "Projects (" + str(temp_df_proj.projName.nunique()) + ") & Versions (" + \
    #                 str(temp_df_proj.projVerId.nunique()) + ")"
    #
    # comptab_label = "Components (" + str(temp_df_comp.compName.nunique()) + ")"
    #
    # vulntab_label = "Vulnerabilities (" + str(temp_df_vuln.vulnId.nunique()) + ")"

    # lictab_table_lics

    # # Click on projtab_treemap
    # if click_proj['points'][0]['parent'] == '':
    #     # All
    #     pass
    # elif click_proj['points'][0]['parent'] == 'All':
    #     # Project
    #     temp_df_proj = temp_df_proj[temp_df_proj.projName == click_proj['points'][0]['label']]
    # else:
    #     # ProjectVersion
    #     temp_df_proj = temp_df_proj[(temp_df_proj.projName == click_proj['points'][0]['parent']) &
    #                                 (temp_df_proj.projVerName == click_proj['points'][0]['label'])]
    #

    return  (dbc.Tabs(
                [
                    dbc.Tab(  # SUMMARY TAB
                        create_projsummtab(df_proj, proj_radio), label="Projects Summary",
                        tab_id="tab_projsummary", id="tab_projsummary",
                    ),
                    dbc.Tab(  # PROJECTS TAB
                        create_projtab(df_proj),
                        label="Projects (" + str(df_proj.projName.nunique()) + ") & Versions (" +
                              str(df_proj.projVerId.nunique()) + ")",
                        tab_id="tab_projects", id="tab_projects"
                    ),
                    dbc.Tab(  # COMPONENTS TAB
                        create_comptab(df_comp),
                        label="Components (" + str(df_main.compName.nunique()) + ")",
                        tab_id="tab_components", id="tab_components"
                    ),
                    dbc.Tab(  # VULNS TAB
                        create_vulntab(df_vuln),
                        label="Vulnerabilties (" + str(df_vuln.vulnId.nunique()) + ")",
                        tab_id="tab_vulns", id="tab_vulns"
                    ),
                    dbc.Tab(  # LICENSE TAB
                        create_lictab(df_lic),
                        label="Licenses (" + str(df_lic.licName.nunique()) + ")",
                        tab_id="tab_lics", id="tab_lics"
                    )
                ],
                id="tabs",
                active_tab="tab_projsummary",
            ), sel_vers_options, sel_tiers_options, sel_dists_options, sel_phases_options, sel_comps_options)


if __name__ == '__main__':
    app.run_server(debug=True)
