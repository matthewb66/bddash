import json
import sys
import os
# from time import time
import dash
import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
import pandas as pd
from flask_caching import Cache

# import dash_auth
import db
import data
import lictab
import vulntab
import comptab
import projtab
import projsumm
import poltab
import overviewtab

# df_main = {}
# df_vuln = {}
# df_vuln_viz = {}
# df_pol = {}
# df_pol_viz = {}
# df_polmap = {}
# df_proj = {}
# df_proj_viz = {}
# df_comp = {}
# df_comp_viz = {}
# df_lic = {}
# df_lic_viz = {}
# df_projcompmap = {}
# df_vulnmap = {}
# df_vulnactivelist = {}
# # lic_compverid_dict = None
# # compverid_lic_dict = None
# df_projphasepolsec = {}
# df_projdistpol = {}
# childdata = {}
# df_comppolsec = {}
#
# serverlist = []
# serverurl = {}

# projlist = {}
# verlist = {}
# complist = {}

expand_child_projects = False

# auth = None
lastdbreadtime = 0


def isempty(val):
    if val is None:
        return True
    if len(val) == 0:
        return True
    return False


def read_data_files():
    if not os.path.isfile('data/db_projs.json') or not os.path.isfile('data/db_vulns.json') or \
            not os.path.isfile('data/db_pols.json'):
        sys.exit(3)

    with open('data/db_projs.json') as jsonproj_file:
        dbprojdata = json.load(jsonproj_file)
    jsonproj_file.close()
    thisdfprojs = pd.read_json(dbprojdata, orient='split')

    with open('data/db_vulns.json') as jsonvuln_file:
        dbvulndata = json.load(jsonvuln_file)
    jsonvuln_file.close()
    thisdfvulns = pd.read_json(dbvulndata, orient='split')

    with open('data/db_pols.json') as jsonpol_file:
        dbpoldata = json.load(jsonpol_file)
    jsonpol_file.close()
    thisdfpols = pd.read_json(dbpoldata, orient='split')

    return thisdfprojs, thisdfvulns, thisdfpols


# def write_data_files(maindf, vulndf, poldf):
#     # from app import df_main, df_vuln
#     jsonout = maindf.to_json(orient="split")
#     o = open("data/db_projs.json", "w")
#     o.write(json.dumps(jsonout, indent=4))
#     o.close()
#
#     jsonout = vulndf.to_json(orient="split")
#     o = open("data/db_vulns.json", "w")
#     o.write(json.dumps(jsonout, indent=4))
#     o.close()
#
#     jsonout = poldf.to_json(orient="split")
#     o = open("data/db_pols.json", "w")
#     o.write(json.dumps(jsonout, indent=4))
#     o.close()
#     print("Done\n")


app = dash.Dash(external_stylesheets=[dbc.themes.COSMO])

server = app.server

cache = Cache(app.server, config={
    # 'CACHE_TYPE': 'redis',
    # Note that filesystem cache doesn't work on systems with ephemeral
    # filesystems like Heroku.
    'CACHE_TYPE': 'filesystem',
    'CACHE_DIR': 'cache-directory',
    'CACHE_DEFAULT_TIMEOUT': 3600,


    # should be equal to maximum number of users on the app at a single time
    # higher numbers will store more data in the filesystem / redis cache
    'CACHE_THRESHOLD': 10
})

# if not os.path.isfile('conf/users.txt'):
#     print('No users.txt file - exiting')
#     sys.exit(3)
#
# with open('conf/users.txt') as f:
#     fdata = f.read()
#     VALID_USERNAME_PASSWORD_PAIRS = json.loads(fdata)
#     f.close()
#
# # app = dash.Dash(external_stylesheets=[dbc.themes.COSMO])
# app.auth = dash_auth.BasicAuth(
#     app,
#     VALID_USERNAME_PASSWORD_PAIRS
# )


# @cache.memoize(timeout=3600)
def proc_comp_data(thisdf, expand):
    # compdf will have 1 row per compver across all projvers
    # -  license risk will be the most severe across all projvers
    # projcompdf will have 1 row for each compver within each projver
    # - will map projverid to compverid

    thisdf.astype(
        {
            'projname': str,
            'projvername': str,
            'projid': str,
            'projverid': str,
            'projverdist': str,
            'projverphase': str,
            'projtier': str,
            'compid': str,
            'compname': str,
            'compverid': str,
            'compvername': str,
            'seccritcount': int,
            'secmedcount': int,
            'seclowcount': int,
            'secokcount': int,
            'lichighcount': int,
            'licmedcount': int,
            'liclowcount': int,
            'licokcount': int,
            'licname': str,
        }
    )

    # Calculate mapping of projvers to compvers
    projcompmapdf = thisdf[['projverid', 'compverid']]

    projdf = thisdf
    projdf["All"] = "All"

    projdf = pd.DataFrame(projdf.eval('secAll = seccritcount + sechighcount + secmedcount + seclowcount'))
    projdf = pd.DataFrame(projdf.eval('seccrithighcountplus1 = seccritcount + sechighcount + 1'))
    projdf = pd.DataFrame(projdf.eval('seccritcountplus1 = seccritcount + 1'))
    projdf = pd.DataFrame(projdf.eval('lichighcountplus1 = lichighcount + 1'))
    # projdf['projverurl'] = serverurl + '/api/projects/' + projdf['projid'].astype(str) + '/versions/' \
    #     + projdf['projverid'] + '/components'

    # Sum columns for projVers
    sums = projdf.groupby("projverid").sum().reset_index()
    # Count components in projvers
    df_counts = pd.DataFrame(projdf['projverid'].value_counts(ascending=False).
                             rename_axis('projverid').reset_index(name='compcount'))
    # Merge compcount into df
    projdf = pd.merge(projdf, df_counts, on='projverid')
    # Remove duplicate component rows
    projdf.drop_duplicates(subset="projverid", keep="first", inplace=True)
    # Remove duplicate and unwanted columns before merge
    projdf.drop(['secAll', 'seccrithighcountplus1', 'seccritcountplus1', 'lichighcountplus1',
                 'seccritcount', 'sechighcount', 'secmedcount',
                 'seclowcount', 'secokcount', 'lichighcount', 'licmedcount', 'liclowcount', 'licokcount', 'compid',
                 'compname', 'compverid', 'compvername', 'licname'], axis=1, inplace=True)
    # Merge sums into df
    projdf = pd.merge(projdf, sums, on='projverid')
    print('{} Projects and {} Versions returned'.format(projdf.projname.nunique(), projdf.projverid.nunique()))

    projdf = projdf.set_index('projverid', drop=True)
    projdf = projdf.sort_index()

    # compdf = tempdf
    # remove duplicates
    compdf = thisdf
    compdf = compdf.drop_duplicates(subset="compverid", keep="first", inplace=False)

    # sort by license risk
    # compdf = compdf.sort_values(by=['lichighcount', 'licmedcount', 'liclowcount'], ascending=False)

    # Calculate license risk value as licrisk
    def calc_license(row):
        if row['lichighcount'] > 0:
            return 'High'
        elif row['licmedcount'] > 0:
            return 'Medium'
        elif row['liclowcount'] > 0:
            return 'Low'
        elif row['licokcount'] > 0:
            return 'OK'
        return ''

    testdf = compdf.apply(calc_license, axis=1, result_type='expand')
    compdf.insert(5, 'licrisk', testdf)
    compdf = compdf.drop(["projname", "projvername", "projverid", "projverdist", "projverphase", "projtier"],
                         axis=1, inplace=False)

    # compdf = compdf.sort_values(by=['compname'], ascending=True)

    def calc_lic_nounknown(row):
        if row['licname'] == 'Unknown License':
            return 1
        else:
            return 0

    # compdf[['licriskNoUnk']] = compdf.apply(calc_lic_nounknown, axis=1)
    testdf = compdf.apply(calc_lic_nounknown, axis=1, result_type='expand')
    compdf.insert(5, 'licriskNoUnk', testdf)

    compdf = compdf.set_index('compverid', drop=True)
    compdf = compdf.sort_index()

    # Create maps of projs to comps and comps to projs
    projcompmapdf = projcompmapdf.set_index('projverid', drop=True)
    projcompmapdf = projcompmapdf.sort_index()

    # projcompmapdf = projcompmapdf.sort_values(['projverid', 'compverid'], ascending=False)

    print('{} Components and {} Component Versions returned'.format(compdf.compname.nunique(), len(compdf)))

    # Process projects in projects
    projchildmap = {}
    childprojlist = []
    comps_as_projs = 0
    comps_as_projs_parents = 0
    labels = []
    tuples = []
    projdf['parent'] = False
    projdf['child'] = False
    count = 1
    print("Processing projects within projects:")
    for testid in projdf.index.unique():
        if count % 100 == 0:
            print("- Projects = {}".format(count))
        count += 1
        projsusingcompdf = projcompmapdf[projcompmapdf.compverid == testid]
        if len(projsusingcompdf) > 0:
            # testid is a project and component
            projdf.loc[testid, 'child'] = True

            # Find projs where it is used
            comps_as_projs += 1
            usedinprojids = projsusingcompdf.index.unique()
            for projverid in usedinprojids:
                projdf.loc[testid, 'parent'] = True

                df = projdf.loc[projverid]
                parent = '//'.join((df['projname'], df['projvername']))
                df = projdf.loc[testid]
                child = '//'.join((df['projname'], df['projvername']))

                # add components from child project (testid) to parent project (projverid)
                # newcomps = df.replace({testid: projverid}, inplace=False)
                if expand:
                    try:
                        newcomps = projcompmapdf.loc[testid].replace({testid: projverid}, inplace=False)
                        # projcompmapdf.append(newcomps)

                        # Remove the component (child project) testid from projverid in projcompmap
                        uncomp = projcompmapdf[~((projcompmapdf.compverid == testid) &
                                                 (projcompmapdf.index == projverid))]
                        projcompmapdf = pd.concat([uncomp, newcomps])
                    except:
                        pass

                comps_as_projs_parents += 1
                childprojlist.append(testid)
                if child not in labels:
                    labels.append(child)
                if projverid in projchildmap.keys():
                    projchildmap[projverid].append(testid)
                else:
                    projchildmap[projverid] = [testid]
                    labels.append(parent)
                print('Parent = ' + parent + ' - Child = ' + child)
                tuples.append((labels.index(parent), labels.index(child)))

    sources = []
    targets = []
    values = []

    for tup in tuples:
        sources.append(tup[0])
        targets.append(tup[1])
        sp = labels[tup[1]].split('//')
        val = projdf[(projdf.projname == sp[0]) & (projdf.projvername == sp[1])].compcount.values[0]
        values.append(val)

    projdf['parent'] = False
    projdf['child'] = False
    for proj in projchildmap.keys():
        projdf.loc[proj, 'parent'] = True
    for child in childprojlist:
        projdf.loc[child, 'child'] = True

    print("Found {} sub-projects within {} projects".format(comps_as_projs, comps_as_projs_parents))

    childdata = {
        'labels': labels,
        'sources': sources,
        'targets': targets,
        'values': values,
    }

    # childdata = {
    #     'parentlabels': ["parent1", "parent2", "parent3"],
    #     'childlabels': ["child1", "child2", "child3"],
    #     'sources': [3, 2, 1, 4],
    #     'targets': [2, 1, 1, 3],
    #     'values': [1, 1, 1, 1],
    # }

    return projdf, compdf, projcompmapdf, childdata


# @cache.memoize(timeout=3600)
def proc_licdata(thisdf):
    # licnames = thisdf.licname.values
    # compids = thisdf.index.unique()
    # licrisks = thisdf.licrisk.values

    # thislic_compverid_dict = {}  # Map of license names to compverids (dict of lists of compverids)
    # thiscompverid_lic_dict = {}  # Map of compverids to licnames (dict of lists of licnames)
    # licrisk_dict = {}
    # licname_list = []

    tempdf = thisdf
    # sums = tempdf[~tempdf['licname'].str.startswith('(') &
    #               ~tempdf['licname'].str.endswith(')')].groupby("licname").sum().reset_index()
    sums = tempdf.groupby("licname").sum().reset_index()
    # print(sums.head(100).to_string())

    # compindex = 0

    # def get_maxlicrisk(riskarray):
    #     for risk in ['High', 'Medium', 'Low', 'OK']:
    #         if risk in riskarray:
    #             return risk

    # for lic in sums.licname.unique():
    #     if lic not in licname_list:
    #         licname_list.append(lic)
    #
    #
    # splits = [lic]
    #
    # if lic[0] == '(' and lic[-1] == ')':
    #     lic = lic[1:-1]
    #     if ' AND ' in lic or ' OR ' in lic:
    #         splits = re.split(' OR | AND ', lic)
    #
    # for item in splits:
    #     # lics = thisdf[thisdf['licname'] == item].licrisk.unique()
    #     # maxrisk = get_maxlicrisk(lics)
    #     compverid = compids[compindex]
    #     if item not in thislic_compverid_dict.keys():
    #         thislic_compverid_dict[item] = [compverid]
    #     elif compverid not in thislic_compverid_dict[item]:
    #         thislic_compverid_dict[item].append(compverid)
    #
    #     if compverid not in thiscompverid_lic_dict.keys():
    #         thiscompverid_lic_dict[compverid] = [item]
    #     elif item not in thiscompverid_lic_dict[compverid]:
    #         thiscompverid_lic_dict[compverid].append(item)

    # licrisk_dict[item] = maxrisk
    # print(item, ' - ', maxrisk, ' - ', lic)

    # compindex += 1

    # print(list(zip(licmap_dict.keys(), licrisk_dict.values())))
    print("{} Licenses returned".format(len(sums)))
    # temp_df = pd.DataFrame.from_records(list(zip(licmap_dict.keys(),
    #                                     licrisk_dict.values())), columns=['licname', 'licrisk'])
    # sorter = ['OK', 'Low', 'Medium', 'High']
    # temp_df.licrisk = temp_df.licrisk.astype("category")
    # temp_df.licrisk.cat.set_categories(sorter, inplace=True)
    return sums


# @cache.memoize(timeout=3600)
def proc_vuln_data(thisdf):
    # vulndf will have 1 row per vulnid
    # projvulnmapdf will have 1 row for each vuln within each projver
    # - will map projverid to compverid

    # thisdf = thisdf.astype(
    #     {
    #         'projverid': str,
    #         'compid': str,
    #         'compverid': str,
    #         'compname': str,
    #         'compvername': str,
    #         'projvername': str,
    #         'projname': str,
    #         'vulnid': str,
    #         'relatedvulnid': str,
    #         'vulnsource': str,
    #         'severity': str,
    #         'score': float,
    #         'remstatus': str,
    #         'solution': bool,
    #         'workaround': bool,
    #         'pubdate': str,
    #         'description': str,
    #         'targetdate': str,
    #         'actualdate': str,
    #         'comment': str,
    #         'attackvector': str,
    #         'updateddate': str,
    #     }
    # )

    vuln_active_list = thisdf[thisdf['remstatus'].isin(['NEW', 'NEEDS_REVIEW', 'REMEDIATION_REQUIRED'])].vulnid.unique()
    # vuln_inactive_list = vulndf[~vulndf['remstatus'].isin(['NEW', 'NEEDS_REVIEW',
    #                                                          'REMEDIATION_REQUIRED'])].vulnid.unique()

    vulndf = thisdf.drop_duplicates(subset=["vulnid"], keep="first", inplace=False)
    # vulndf = vulndf.sort_values(by=['score'], ascending=False)
    vulndf = vulndf.drop(["projname", "projvername", "compname", "compid", "compverid",
                          "compvername", "remstatus"],
                         axis=1, inplace=False)

    vulndf = vulndf.set_index('vulnid', drop=False)
    vulndf = vulndf.sort_index()

    vulnmapdf = thisdf[["vulnid", "projverid", "compverid"]]
    vulnmapdf = vulnmapdf.set_index('vulnid', drop=False)
    vulnmapdf = vulnmapdf.sort_index()

    print('{} Vulnerabilities returned'.format(len(vulndf)))
    return vulndf, vulnmapdf, vuln_active_list


# @cache.memoize(timeout=3600)
def proc_pol_data(projdf, compdf, poldf):
    def tm_sorter(column):
        """Sort function"""
        severities = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'TRIVIAL', 'UNSPECIFIED']
        correspondence = {polseverity: order for order, polseverity in enumerate(severities)}
        return column.map(correspondence)

    poldf = poldf.astype(
        {
            'projverid': str,
            'compverid': str,
            'polid': str,
            'polname': str,
            'polstatus': str,
            'overrideby': str,
            'desc': str,
            'polseverity': str,
        }
    )

    poldf.sort_values(by='polseverity', key=tm_sorter, inplace=True, ascending=True)
    polmapdf = poldf[['polid', 'projverid', 'compverid']]
    # Add policies to projects
    # SELECT
    # component_policies.project_version_id as projverid,
    # component.component_version_id as compverid,
    # policy_id as polid,
    # policy_name as polname,
    # policy_status as polstatus,
    # overridden_by as overrideby,
    # description as desc,
    # polseverity

    tempdf = poldf.drop_duplicates(subset=["projverid"], keep="first", inplace=False)
    projdf = pd.merge(projdf, tempdf, on='projverid', how='outer')
    projdf.fillna(value='', inplace=True)
    projdf = projdf.set_index('projverid', drop=False)
    projdf = projdf.sort_index()

    tempdf = poldf.drop_duplicates(subset=["compverid"], keep="first", inplace=False)
    compdf = pd.merge(compdf, tempdf, on='compverid', how='outer')
    compdf.fillna(value='', inplace=True)
    compdf = compdf.drop_duplicates(subset=["compverid"], keep="first", inplace=False)
    compdf = compdf.set_index('compverid', drop=False)
    compdf = compdf.sort_index()

    poldf = poldf.drop_duplicates(subset=["polid"], keep="first", inplace=False)
    print('{} Policies returned'.format(poldf.polid.nunique()))

    poldf = poldf.set_index('polid', drop=False)
    poldf = poldf.sort_index()

    return projdf, compdf, poldf, polmapdf


# @cache.memoize(timeout=3600)
def proc_overviewdata(projdf, compdf):
    # Need counts of projects by:
    # - Phase
    # - Policy severity risk
    # - Security risk
    # Need counts of components by:
    # - Policy severity risk
    # - Security risk

    tempdf = projdf[['polseverity']].mask(projdf['polseverity'] == '', 'NONE', inplace=False)
    projdf['polseverity'] = tempdf['polseverity']

    def calc_security(row):
        if row['seccritcount'] > 0:
            return 'CRITICAL'
        elif row['sechighcount'] > 0:
            return 'HIGH'
        elif row['secmedcount'] > 0:
            return 'MEDIUM'
        elif row['seclowcount'] > 0:
            return 'LOW'
        elif row['secokcount'] > 0:
            return 'OK'
        return 'NONE'

    proj_phasepolsecdf = projdf[['projverid', 'projvername', 'projid', 'projverdist',
                                 'projverphase', 'All', 'compcount', 'secAll', 'polseverity', 'seccritcount',
                                 'sechighcount', 'secmedcount', 'seclowcount', 'secokcount']]
    testdf = proj_phasepolsecdf.apply(calc_security, axis=1, result_type='expand')
    proj_phasepolsecdf.insert(5, 'secrisk', testdf)
    tempdf = proj_phasepolsecdf.groupby(["projverphase", "polseverity", "secrisk"]).count().reset_index()
    proj_phasepolsecdf = proj_phasepolsecdf.groupby(["projverphase", "polseverity", "secrisk"]).max().reset_index()
    # proj_phasepolsecdf = pd.merge(proj_phasepolsecdf, tempdf['projname'])
    proj_phasepolsecdf.insert(5, 'projcount', tempdf['projvername'])

    # temp_df = projdf.groupby(["projverphase", "polseverity", "secrisk"]).count().reset_index()
    # proj_phasepolsecdf['projcount'] = temp_df['projname']

    comp_polsecdf = compdf
    tempdf = comp_polsecdf[['polseverity']].mask(comp_polsecdf['polseverity'] == '', 'NONE', inplace=False)
    comp_polsecdf['polseverity'] = tempdf['polseverity']

    testdf = comp_polsecdf.apply(calc_security, axis=1, result_type='expand')
    comp_polsecdf.insert(5, 'secrisk', testdf)
    tempdf = comp_polsecdf.groupby(["polseverity"]).count().reset_index()
    comp_polsecdf = comp_polsecdf.groupby(["polseverity"]).sum().reset_index()
    comp_polsecdf.insert(5, 'compcount', tempdf['compverid'])

    comp_polsecdf.drop(['licriskNoUnk',
                        'lichighcount', 'compcount', 'licmedcount', 'liclowcount', 'licokcount'], axis=1, inplace=True)

    return proj_phasepolsecdf, comp_polsecdf


@cache.memoize(timeout=3600)
def get_server_data(pocserver):
    dbconfig = 'conf/database.' + pocserver
    
    # serverlist.append(pocserver)
    
    app.lastdbreadtime = 0
    if True:  # DEBUG - read from DB
        if not os.path.isfile(dbconfig):
            print('\nNo conf/database.ini or data files - exiting')
            sys.exit(3)

        # statusitem = ''
        print('\nWill read data from DB connection')
        conn, cur = db.connect(dbconfig)
        print("Getting component data ...")
        df_main = db.get_projdata(conn)
        print("Getting vulnerability data ...")
        df_vuln = db.get_vulndata(conn)
        print("Getting policy data ...")
        df_pol = db.get_poldata(conn)
        db.close_conn(conn, cur)
    else:
        print('\nWill read data from json files')
        df_main, df_vuln, df_pol = read_data_files()
        # statusitem = dbc.NavItem(dbc.NavLink("Status: Data from Files", href='#', disabled=True))
    
    if isempty(df_main) or isempty(df_vuln) or isempty(df_pol):
        print("No data obtained from DB")
        sys.exit(2)
    
    # if readfrom == 'db':
    #     print("Writing data to JSON files ...")
    #     write_data_files(df_main, df_vuln, df_pol)
    
    df_proj, df_comp, df_projcompmap, childdata = \
        proc_comp_data(df_main, expand_child_projects)
    df_main = None
    df_comp_viz = df_comp
    # df_proj = data.proc_projdata(df_main)
    df_proj_viz = df_proj
    # print(df_proj)
    df_vuln, df_vulnmap, df_vulnactivelist = \
        proc_vuln_data(df_vuln)
    df_vuln_viz = df_vuln
    df_lic = data.proc_licdata(df_comp)
    df_lic_viz = df_lic
    df_proj, df_comp, df_pol, df_polmap = \
        proc_pol_data(df_proj, df_comp, df_pol)
    df_pol_viz = df_pol
    # data.proc_projinproj(df_proj, df_comp)
    df_projphasepolsec, df_comppolsec = \
        proc_overviewdata(df_proj, df_comp)

    # projlist = [
    #         {'label': i, 'value': i} for i in
    #         df_proj.sort_values(by=['projname'], ascending=True).projname.unique()
    #     ]
    #
    # verlist = [
    #         {'label': i, 'value': i} for i in
    #         df_proj.sort_values(by=['projvername'], ascending=True).projvername.unique()
    #     ]
    #
    # complist = [
    #         {'label': i, 'value': i} for i in
    #         df_comp.sort_values(by=['compname'], ascending=True).compname.unique()
    #     ]
    
    return df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, \
        df_lic, df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, \
        childdata, df_comppolsec


def create_alltabs(projdata, compdata, vulndata, licdata, poldata, projphasepoldata, comppolsecdata,
                   child_data,
                   colorfield, sizefield, noprojs, pocserver):

    try:
        if noprojs or isempty(pocserver) or isempty(projdata):
            return dbc.Tabs(
                [
                    dbc.Tab(  # OVERVIEW TAB
                        html.H1(children='No Projects Selected by Filters'),
                        label="Overview",
                        tab_id="tab_overview", id="tab_overview"
                    ),
                    dbc.Tab(  # SUMMARY TAB
                        [
                            html.H1(children='No Projects Selected by Filters'),
                            dbc.RadioItems(
                                options=[
                                    # {'label': 'Critical Vulns', 'value': 'seccritcount'},
                                    # {'label': 'High Vulns', 'value': 'sechighcount'},
                                    # {'label': 'High Licenses', 'value': 'lichighcount'},
                                ],
                                id='summtab_color_radio',
                                value=colorfield,
                                inline=True,
                                # labelStyle={'display': 'inline-block'}
                            ),
                            dbc.RadioItems(
                                options=[
                                    # {'label': 'Critical Vulns', 'value': 'seccritcount'},
                                    # {'label': 'High Vulns', 'value': 'sechighcount'},
                                    # {'label': 'High Licenses', 'value': 'lichighcount'},
                                ],
                                id='summtab_size_radio',
                                value=sizefield,
                                inline=True,
                                # labelStyle={'display': 'inline-block'}
                            ),
                        ],
                        label="Projects Summary",
                        tab_id="tab_projsummary", id="tab_projsummary",
                    ),
                    dbc.Tab(  # PROJECTS TAB
                        html.H1(children='No Projects Selected by Filters'),
                        label="Projects (0) & Versions (0)",
                        tab_id="tab_projects", id="tab_projects"
                    ),
                    dbc.Tab(  # COMPONENTS TAB
                        html.H1(children='No Projects Selected by Filters'),
                        label="Components (0)",
                        tab_id="tab_components", id="tab_components"
                    ),
                    dbc.Tab(  # VULNS TAB
                        html.H1(children='No Projects Selected by Filters'),
                        label="Vulnerabilties (0)",
                        tab_id="tab_vulns", id="tab_vulns"
                    ),
                    dbc.Tab(  # POLICY TAB
                        html.Div(children='No Policies Selected by Filters'),
                        label="Policies (0)",
                        # label="Licenses",
                        tab_id="tab_pols", id="tab_pols"
                    ),
                    dbc.Tab(  # LICENSE TAB
                        html.Div(children='No Projects Selected by Filters'),
                        label="Licenses (0)",
                        # label="Licenses",
                        tab_id="tab_lics", id="tab_lics"
                    )
                ],
                id="tabs",
                active_tab='tab_overview',
            )
    except Exception as exc:
        print("exception")
        print(exc)

    if not isempty(projdata):
        projtext = "Projects (" + str(projdata.projid.nunique()) + ") & Versions (" + \
                   str(projdata.projverid.nunique()) + ")"
    else:
        projtext = "Projects (0)"

    if not isempty(compdata):
        comptext = "Components (" + str(compdata.compverid.nunique()) + ")"
    else:
        comptext = "Components(0)"

    if not isempty(vulndata):
        vulntext = "Vulnerabilties (" + str(len(vulndata)) + ")"
    else:
        vulntext = "Vulnerabilities (0)"

    if not isempty(licdata):
        lictext = "Licenses (" + str(licdata.licname.nunique()) + ")"
    else:
        lictext = "Licenses (0)"

    if isempty(poldata):
        poltext = "Policies (" + str(poldata.polid.nunique()) + ")"
    else:
        poltext = "Policies (0)"

    return dbc.Tabs(
        [
            dbc.Tab(  # OVERVIEW TAB
                overviewtab.create_overviewtab(projdata, projphasepoldata, comppolsecdata, child_data),
                label="Overview",
                tab_id="tab_overview", id="tab_overview",
            ),
            dbc.Tab(  # SUMMARY TAB
                projsumm.create_projsummtab(projdata, colorfield, sizefield),
                label="Projects Summary",
                tab_id="tab_projsummary", id="tab_projsummary",
            ),
            dbc.Tab(  # PROJECTS TAB
                projtab.create_projtab(projdata),
                label=projtext,
                tab_id="tab_projects", id="tab_projects"
            ),
            dbc.Tab(  # COMPONENTS TAB
                comptab.create_comptab(compdata),
                label=comptext,
                tab_id="tab_components", id="tab_components"
            ),
            dbc.Tab(  # VULNS TAB
                vulntab.create_vulntab(vulndata),
                label=vulntext,
                tab_id="tab_vulns", id="tab_vulns"
            ),
            dbc.Tab(  # POLICY TAB
                poltab.create_poltab(poldata),
                label=poltext,
                tab_id="tab_pols", id="tab_pols",
            ),
            dbc.Tab(  # LICENSE TAB
                lictab.create_lictab(licdata),
                label=lictext,
                # label="Licenses",
                tab_id="tab_lics", id="tab_lics"
            )
        ],
        id="tabs",
        # active_tab=activetab,
    )


app.layout = dbc.Container(
    [
        # 		dcc.Store(id='sec_values', storage_type='local'),
        # 		dcc.Store(id='lic_values', storage_type='local'),
        dcc.Location(id='thispath', refresh=True),
        dcc.Store(id='store_pocserver', storage_type='session'),
        dcc.Store(id='proj_color', storage_type='session'),
        dcc.Store(id='proj_size', storage_type='session'),
        dcc.Store(id='sankey_state', storage_type='session'),
        # dcc.Store(id='active_tab', storage_type='session'),
        dbc.NavbarSimple(
            children=[
                dbc.NavItem(dbc.NavLink("Status: Data from Reporting DB", href='#', disabled=True)),
                dbc.NavItem(dbc.NavLink("No POC Server", href='#', disabled=True, id='poc_server')),
                dbc.NavItem(dbc.NavLink("Documentation", href="https://github.com/matthewb66/bddash")),
            ],
            brand="Black Duck Analysis Console",
            # brand_href=serverurl,
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
                        # options=projlist,
                        multi=True,
                        placeholder='Select Projects ...'
                    ), width=3,
                    align='center',
                ),
                dbc.Col(html.Div(children="Versions"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_versions",
                        # options=verlist,
                        multi=True,
                        placeholder='Select Versions ...'
                    ), width=3,
                    align='center',
                ),
                dbc.Col(html.Div(children="Components"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_comps",
                        # options=complist,
                        multi=True
                    ), width=3,
                    align='center',
                ),
            ]
        ),
        dbc.Row(
            [
                dbc.Col(html.Div(children="Vuln Status"), width=1, align='center',
                        # style={'font-size': '14px'},
                        ),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_remstatus",
                        options=[
                            {'label': 'UNREMEDIATED', 'value': 'UNREMEDIATED'},
                            {'label': 'REMEDIATED', 'value': 'REMEDIATED'},
                            # {'label': 'New', 'value': 'NEW'},
                            # {'label': 'NeedsRev', 'value': 'NEEDS_REVIEW'},
                            # {'label': 'Patched', 'value': 'PATCHED'},
                            # {'label': 'RemReq', 'value': 'REMEDIATION_REQUIRED'},
                            # {'label': 'Remdtd', 'value': 'REMEDIATED'},
                            # {'label': 'Ignored', 'value': 'IGNORED'},
                        ],
                        value=['UNREMEDIATED'],
                        multi=True
                    ), width=2,
                    align='center',
                ),
                dbc.Col(html.Div(children="Security Risk"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_secrisk",
                        options=[
                            {'label': 'Crit', 'value': 'Critical'},
                            {'label': 'High', 'value': 'High'},
                            {'label': 'Med', 'value': 'Medium'},
                            {'label': 'Low', 'value': 'Low'},
                        ],
                        multi=True
                    ), width=2,
                    align='center',
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
                    ), width=2,
                    align='center',
                ),
                dbc.Col(html.Div(children="Policy Severity"), width=1, align='center',
                        style={'font-size': '14px'},
                        ),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_polsev",
                        options=[
                            {'label': 'BLOCKER', 'value': 'BLOCKER'},
                            {'label': 'CRITICAL', 'value': 'CRITICAL'},
                            {'label': 'MAJOR', 'value': 'MAJOR'},
                            {'label': 'MINOR', 'value': 'MINOR'},
                            {'label': 'TRIVIAL', 'value': 'TRIVIAL'},
                            {'label': 'UNSPECIFIED', 'value': 'UNSPECIFIED'},
                        ],
                        multi=True
                    ), width=2,
                    align='center',
                ),
                dbc.Col(html.Div(children="Tiers"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_tiers",
                        # options=[
                        #     {'label': i, 'value': i} for i in df_proj.projtier.unique()
                        # ],
                        multi=True
                    ), width=2,
                    align='center',
                ),
                dbc.Col(html.Div(children="Distribution"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_dists",
                        # options=[
                        #     {'label': i, 'value': i} for i in df_proj.projverdist.unique()
                        # ],
                        multi=True
                    ), width=2,
                    align='center',
                ),
                dbc.Col(html.Div(children="Phase"), width=1, align='center'),
                dbc.Col(
                    dcc.Dropdown(
                        id="sel_phases",
                        # options=[
                        #     {'label': i, 'value': i} for i in df_proj.projverphase.unique()
                        # ],
                        multi=True
                    ), width=2,
                    align='center',
                ),
                dbc.Col(
                    dbc.Button("Apply Filters", id="sel-button", className="mr-2", size='md'),
                    width={"size": 2, "offset": 1},
                    # width=2,
                    align='center',
                ),
            ]
        ),
        dbc.Row(html.Hr()),
        dbc.Row(
            dbc.Col(
                dbc.Spinner(
                    # create_alltabs(df_proj, df_comp, df_vuln, df_lic, df_pol, df_projphasepolsec, df_comppolsec,
                    #                childdata,
                    #                'lichighcountplus1', 'seccritcountplus1', False, None),
                    create_alltabs(None, None, None, None, None, None, None,
                                   None,
                                   'lichighcountplus1', 'seccritcountplus1', True, None),
                    id='spinner_main',
                ), width=12,
            )
        ),
    ], fluid=True
)


@app.callback(
    Output('lictab_card_lic', 'children'),
    [
        Input('sel_lic_button', 'n_clicks'),
        State('lictab_table_lics', 'derived_virtual_data'),
        State('lictab_table_lics', 'derived_virtual_selected_rows'),
        State('store_pocserver', 'data'),
    ]
)
def callback_lictab_sellic_button(nclicks, cdata, rows, pocserver):
    print('callback_lictab_sellic_button')

    df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, df_lic, \
        df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, childdata, \
        df_comppolsec = get_server_data(pocserver)

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return lictab.create_lictab_card_lic(df_proj_viz, df_comp_viz, df_projcompmap, lic_compverid_dict,
        #                                      df_lic_viz[df_lic_viz['licname'] == cdata[rows[0]][
        #                                             'licname']])
        return lictab.create_lictab_card_lic(df_proj_viz, df_comp_viz, df_projcompmap,
                                             cdata[rows[0]])

    return lictab.create_lictab_card_lic(None, None, None, None)


@app.callback(
    Output('poltab_card_pol', 'children'),
    [
        Input('sel_pol_button', 'n_clicks'),
        State('poltab_table_pols', 'derived_virtual_data'),
        State('poltab_table_pols', 'derived_virtual_selected_rows'),
        State('store_pocserver', 'data'),
    ]
)
def callback_poltab_selpol_button(nclicks, cdata, rows, pocserver):
    print('callback_poltab_selpol_button')

    df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, df_lic, \
        df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, childdata, \
        df_comppolsec = get_server_data(pocserver)

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return poltab.create_poltab_card_pol(df_proj_viz, df_comp_viz, df_pol,
        #                                      df_pol_viz.loc[cdata[rows[0]]])
        return poltab.create_poltab_card_pol(df_proj_viz, df_comp_viz, df_pol,
                                             cdata[rows[0]])

    return poltab.create_poltab_card_pol(None, None, None, None)


@app.callback(
    [
        Output('tab_comp_subdetail', 'children'),
        Output('comptab_detail_tabs', 'active_tab'),
    ],
    [
        Input('sel_comp_button', 'n_clicks'),
        State('comptab_table_compvers', 'derived_virtual_data'),
        State('comptab_table_compvers', 'derived_virtual_selected_rows'),
        State('store_pocserver', 'data'),
    ]
)
def callback_comptab_selcomp_button(nclicks, cdata, rows, pocserver):
    print('callback_comptab_selcomp_button')

    df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, df_lic, \
        df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, childdata, \
        df_comppolsec = get_server_data(pocserver)

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return comptab.create_comptab_card_comp(df_proj_viz, df_projcompmap, df_polmap,
        #                                         df_comp_viz.loc[cdata[rows[0]]['projverid']]), \
        #        'tab_comp_subdetail'
        return comptab.create_comptab_card_comp(df_proj_viz, df_projcompmap, df_pol,
                                                df_polmap,
                                                cdata[rows[0]]), 'tab_comp_subdetail'

    return comptab.create_comptab_card_comp(None, None, None, None, None), 'tab_comp_subsummary'


@app.callback(
    Output('vulntab_card_vuln', 'children'),
    [
        Input('sel_vuln_button', 'n_clicks'),
        State('vulntab_table_vulns', 'derived_virtual_data'),
        State('vulntab_table_vulns', 'derived_virtual_selected_rows'),
        State('store_pocserver', 'data'),
    ]
)
def callback_vulntab_selvuln_button(nclicks, cdata, rows, pocserver):
    print('callback_vulntab_selvuln_button')

    df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, df_lic, \
        df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, childdata, \
        df_comppolsec = get_server_data(pocserver)

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # print(df_vuln[df_vuln['vulnid'] == cdata[rows[0]]['vulnid']].to_string())
        # return vulntab.create_vulntab_card_vuln(df_proj_viz, df_comp_viz, df_vulnmap,
        #                                         df_vuln_viz.loc[cdata[rows[0]]['vulnid']])
        return vulntab.create_vulntab_card_vuln(df_proj_viz, df_comp_viz, df_vulnmap,
                                                cdata[rows[0]], "https://{}.blackduck.synopsys.com".format(pocserver))

    return vulntab.create_vulntab_card_vuln(None, None, None, None, None)


@app.callback(
    [
        Output('sel_projects', 'value'),
        # Output('sel_versions', 'value'),
    ],
    [
        Input('filter_compcard_proj_button', 'n_clicks'),
        Input('filter_vulncard_proj_button', 'n_clicks'),
        Input('filter_polcard_proj_button', 'n_clicks'),
        Input('filter_thisproj_button', 'n_clicks'),
        Input('filter_usedproj_button', 'n_clicks'),
        Input('projsummtab_graph_proj', 'clickData'),
        State('comptab_card_projtable', 'derived_virtual_data'),
        State('comptab_card_projtable', 'derived_virtual_selected_rows'),
        State('vulntab_card_projtable', 'derived_virtual_data'),
        State('vulntab_card_projtable', 'derived_virtual_selected_rows'),
        State('poltab_card_projtable', 'derived_virtual_data'),
        State('poltab_card_projtable', 'derived_virtual_selected_rows'),
        State('projtab_table_projs', 'derived_virtual_data'),
        State('projtab_table_projs', 'derived_virtual_selected_rows'),
        State('projtab_detail_projtable', 'derived_virtual_data'),
        State('projtab_detail_projtable', 'derived_virtual_selected_rows'),
    ]
)
def callback_filterproj_buttons(compprojclicks, vulnprojclicks, polprojclicks, projclicks, usedprojclicks,
                                treemapprojclick,
                                compprojdata, compprojrows, vulnprojdata, vulnprojrows, polprojdata, polprojrows,
                                projdata, projrows, projuseddata, projusedrows):
    print('callback_filterproj_buttons')

    changed_id = [p['prop_id'] for p in dash.callback_context.triggered][0]

    if compprojdata is not None and 'filter_compcard_proj_button' in changed_id and len(compprojrows) > 0:
        val = compprojdata[compprojrows[0]]['projname']
    elif vulnprojdata is not None and 'filter_vulncard_proj_button' in changed_id and len(vulnprojrows) > 0:
        val = vulnprojdata[vulnprojrows[0]]['projname']
    elif polprojdata is not None and 'filter_polcard_proj_button' in changed_id and len(polprojrows) > 0:
        val = polprojdata[polprojrows[0]]['projname']
    elif projdata is not None and 'filter_thisproj_button' in changed_id and len(projrows) > 0:
        val = projdata[projrows[0]]['projname']
    elif projuseddata is not None and 'filter_usedproj_button' in changed_id and len(projusedrows) > 0:
        val = projuseddata[projusedrows[0]]['projname']
    elif treemapprojclick is not None:
        parent = treemapprojclick['points'][0]['parent']
        label = treemapprojclick['points'][0]['label']
        if parent == 'All':
            val = label
        else:
            val = parent
    else:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    return [val]


@app.callback(
    Output('sel_comps', 'value'),
    [
        Input('filter_vulncard_comp_button', 'n_clicks'),
        Input('filter_compcard_comp_button', 'n_clicks'),
        State('vulntab_card_comptable', 'derived_virtual_data'),
        State('vulntab_card_comptable', 'derived_virtual_selected_rows'),
        State('comptab_table_compvers', 'derived_virtual_data'),
        State('comptab_table_compvers', 'derived_virtual_selected_rows'),
    ]
)
def callback_filtercomp_buttons(vulnclicks, compclicks, vulncdata, vulncrows, compcdata, compcrows):
    print('callback_filtercomp_buttons')

    val = ''
    if vulnclicks is None and compclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate
    elif vulnclicks is not None:
        if vulncrows:
            val = vulncdata[vulncrows[0]]['compname']
    elif compclicks is not None:
        if compcrows:
            val = compcdata[compcrows[0]]['compname']

    return [val]


@app.callback(
    [
        Output('tab_proj_subdetail', 'children'),
        Output('tabs_proj_subtabs', 'active_tab'),
    ],
    [
        Input('sel_proj_button', 'n_clicks'),
        State('projtab_table_projs', 'derived_virtual_data'),
        State('projtab_table_projs', 'derived_virtual_selected_rows'),
        State('store_pocserver', 'data'),
    ]
)
def callback_projtab_selproj_button(nclicks, cdata, rows, pocserver):
    print('callback_projtab_selproj_button')

    df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, df_lic, \
        df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, childdata, \
        df_comppolsec = get_server_data(pocserver)

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        projid = cdata[rows[0]]['projverid']
        mydata = df_proj_viz.loc[projid]
        return projtab.create_projtab_card_proj(df_proj_viz, df_comp_viz, df_pol,
                                                df_projcompmap, df_polmap,
                                                mydata, "https://{}.blackduck.synopsys.com".format(pocserver)), \
               'tab_proj_subdetail'

    return projtab.create_projtab_card_proj(None, None, None, None, None, None, None), 'tab_proj_subsummary'


# Update graphs and select options based on selection inputs
@app.callback(
    [
        Output('spinner_main', 'children'),
        Output('proj_color', 'data'),
        Output('proj_size', 'data'),
        Output('tabs', 'active_tab'),
        Output('poc_server', 'children'),
        Output('store_pocserver', 'data'),
        Output('sel_projects', 'options'),
        Output('sel_versions', 'options'),
        Output('sel_comps', 'options'),
        Output('sel_tiers', 'options'),
        Output('sel_dists', 'options'),
        Output('sel_phases', 'options'),
    ], [
        Input("sel-button", "n_clicks"),
        Input('summtab_color_radio', 'value'),
        Input('summtab_size_radio', 'value'),
        State("tabs", "active_tab"),
        State('sel_projects', 'value'),
        State('sel_versions', 'value'),
        State('sel_remstatus', 'value'),
        State('sel_tiers', 'value'),
        State('sel_dists', 'value'),
        State('sel_phases', 'value'),
        State('sel_secrisk', 'value'),
        State('sel_licrisk', 'value'),
        State('sel_polsev', 'value'),
        # State('sel_ignore_unklic', 'value'),
        State('sel_comps', 'value'),
        State('proj_color', 'data'),
        State('proj_size', 'data'),
        # State('active_tab', 'data'),
        State('store_pocserver', 'data'),
        State('thispath', 'pathname')
    ]
)
def callback_main(nclicks, proj_treemap_color, proj_treemap_size, tab, projs, vers, remstatus,
                  tiers, dists, phases,
                  secrisk, licrisk, polsev, comps, proj_color_prev, proj_size_prev, pocserver, path):

    print('callback_main')

    if pocserver is None or pocserver == '':
        if path is not None and path != '':
            pocserver = str(path).replace('/', '')
        else:
            print("NO ACTION")
            raise dash.exceptions.PreventUpdate

    print("POC Server is " + pocserver)
    df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, df_lic, \
        df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, childdata, \
        df_comppolsec = get_server_data(pocserver)

    temp_df_proj = df_proj
    temp_df_comp = df_comp
    temp_df_vuln = df_vuln
    temp_df_lic = df_lic
    temp_df_pol = df_pol
    noprojs = False

    # Process existing select dropdowns
    if not isempty(projs):
        if isinstance(projs, list):
            temp_df_proj = temp_df_proj[temp_df_proj.projname.isin(projs)]
        else:
            temp_df_proj = temp_df_proj[temp_df_proj['projname'] == projs]

    if (not isempty(vers)) and (not isempty(temp_df_proj)):
        if isinstance(vers, list):
            temp_df_proj = temp_df_proj[temp_df_proj.projvername.isin(vers)]
        else:
            temp_df_proj = temp_df_proj[temp_df_proj['projname'] == vers]

    if (not isempty(dists)) and (not isempty(temp_df_proj)):
        # Filter projects based on distribution selection
        if isinstance(dists, list):
            temp_df_proj = temp_df_proj[temp_df_proj.projverdist.isin(dists)]
        else:
            temp_df_proj = temp_df_proj[temp_df_proj.projverdist == dists]

    if (not isempty(phases)) and (not isempty(temp_df_proj)):
        # Filter projects based on phase selection
        if isinstance(phases, list):
            temp_df_proj = temp_df_proj[temp_df_proj.projverphase.isin(phases)]
        else:
            temp_df_proj = temp_df_proj[temp_df_proj.projverphase == phases]

    if (not isempty(tiers)) and (not isempty(temp_df_proj)):
        # Filter projects based on phase selection
        if isinstance(tiers, list):
            temp_df_proj = temp_df_proj[temp_df_proj.projtier.isin(tiers)]
        else:
            temp_df_proj = temp_df_proj[temp_df_proj.projtier == tiers]

    # Process comps from reduced list of projs
    if (not isempty(temp_df_proj)) and len(temp_df_proj) < len(df_proj):
        projcompmap = df_projcompmap
        temp = projcompmap[projcompmap.index.isin(temp_df_proj.index.unique())].compverid.values
        if len(temp) > 0:
            temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(temp)]
        else:
            temp_df_comp = None

    if (not isempty(comps)) and (not isempty(temp_df_comp)):
        # Filter projects based on phase selection
        if isinstance(comps, list):
            temp_df_comp = temp_df_comp[temp_df_comp.compname.isin(comps)]
        else:
            temp_df_comp = temp_df_comp[temp_df_comp['compname'] == comps]

    if (not isempty(secrisk)) and (not isempty(temp_df_comp)) and (not isempty(temp_df_proj)):
        # Filter projects based on security risk selection
        secvals = []
        temp_df_comp = temp_df_comp[temp_df_comp.seccritcount != '']
        if 'Critical' in secrisk:
            temp_df_comp = temp_df_comp[temp_df_comp.seccritcount > 0]
            secvals.append('CRITICAL')
        if 'High' in secrisk:
            temp_df_comp = temp_df_comp[temp_df_comp.sechighcount > 0]
            secvals.append('HIGH')
        if 'Medium' in secrisk:
            temp_df_comp = temp_df_comp[temp_df_comp.secmedcount > 0]
            secvals.append('MEDIUM')
        if 'Low' in secrisk:
            temp_df_comp = temp_df_comp[temp_df_comp.seclowcount > 0]
            secvals.append('LOW')
        temp_df_vuln = temp_df_vuln[temp_df_vuln.severity.isin(secvals)]

    if (not isempty(licrisk)) and (not isempty(temp_df_comp)) and (not isempty(temp_df_proj)):
        # Filter projects based on security risk selection
        temp_df_comp = temp_df_comp[temp_df_comp.lichighcount != '']

        if 'High' in licrisk:
            temp_df_comp = temp_df_comp[temp_df_comp.lichighcount > 0]

        if 'Medium' in licrisk:
            temp_df_comp = temp_df_comp[temp_df_comp.licmedcount > 0]

        if 'Low' in licrisk:
            temp_df_comp = temp_df_comp[temp_df_comp.liclowcount > 0]

    if (not isempty(polsev)) and (not isempty(temp_df_comp)):
        # Filter projects based on security risk selection
        for sev in ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'TRIVIAL', 'UNSPECIFIED']:
            if sev in polsev:
                temp_df_pol = temp_df_pol[temp_df_pol.polseverity == sev]
        polmap = df_polmap
        comps = polmap[polmap.polid.isin(temp_df_pol.index.values)].compverid.unique()
        temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(comps)]

    if (not isempty(temp_df_comp)) and 0 < len(temp_df_comp) < len(df_comp):
        vulnmap = df_vulnmap
        temp = vulnmap[vulnmap.compverid.isin(temp_df_comp.compverid.unique())].index.values
        if not isempty(temp):
            temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(temp)]
        else:
            temp_df_vuln = None

        projcompmap = df_projcompmap
        temp = projcompmap[projcompmap.compverid.isin(temp_df_comp.index.values)].index.values
        if (not isempty(temp_df_proj)) and (not isempty(temp)):
            temp_df_proj = temp_df_proj[temp_df_proj.index.isin(temp)]
        else:
            temp_df_proj = None

        polmap = df_polmap
        temp = polmap[polmap.compverid.isin(temp_df_comp.compverid.unique())].polid.unique()
        if (not isempty(temp_df_pol)) and (not isempty(temp)):
            temp_df_pol = temp_df_pol[temp_df_pol.polid.isin(temp)]
        else:
            temp_df_pol = None

        # temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(compveridlist)]

    elif (not isempty(temp_df_proj)) and 0 < len(temp_df_proj) < len(df_proj):
        projcompmap = df_projcompmap
        temp = projcompmap[projcompmap.index.isin(temp_df_proj.index.values)].compverid.unique()
        if not isempty(temp):
            temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(temp)]
        else:
            temp_df_comp = None

        vulnmap = df_vulnmap
        temp = vulnmap[vulnmap.projverid.isin(temp_df_proj.index.values)].index.values
        if not isempty(temp):
            temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(temp)]
        else:
            temp_df_vuln = None

        polmap = df_polmap
        temp = polmap[polmap.projverid.isin(temp_df_proj.index.values)].polid.unique()
        if (not isempty(temp_df_pol)) and (not isempty(temp)):
            temp_df_pol = temp_df_pol[temp_df_pol.polid.isin(temp)]
        else:
            temp_df_pol = None

        # temp_df_proj = temp_df_proj[temp_df_proj.projverid.isin(projveridlist)]

    if (not isempty(temp_df_comp)) and 0 < len(temp_df_comp) < len(df_comp):
        licnames = temp_df_comp.licname.unique()
        # for cid in temp_df_comp.compverid.unique():
        #     if cid in compverid_lic_dict.keys():
        #         for lic in compverid_lic_dict[cid]:
        #             if {lic}.intersection(set(licnames)) != {lic}:
        #                 licnames.append(lic)
        #         [licnames.append(x) for x in compverid_lic_dict[cid] if x not in licnames]
        licnames.sort()
        temp_df_lic = temp_df_lic[temp_df_lic.licname.isin(licnames)]

    if (not isempty(remstatus)) and (not isempty(temp_df_vuln)):
        # tempvulnidlist = []
        if {'UNREMEDIATED'}.intersection(set(remstatus)) == {'UNREMEDIATED'}:
            temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(df_vulnactivelist)]
        if {'REMEDIATED'}.intersection(set(remstatus)) == {'REMEDIATED'}:
            temp_df_vuln = temp_df_vuln[~temp_df_vuln.index.isin(df_vulnactivelist)]
        # vulnidlist = pd.merge(vulnidlist, tempvulnidlist, how='inner')

    if isempty(temp_df_proj) or isempty(temp_df_comp):
        noprojs = True

    activetab = tab

    projlist = [
            {'label': i, 'value': i} for i in
            df_proj.sort_values(by=['projname'], ascending=True).projname.unique()
        ]
    verlist = [
            {'label': i, 'value': i} for i in
            df_proj.sort_values(by=['projvername'], ascending=True).projvername.unique()
        ]
    complist = [
            {'label': i, 'value': i} for i in
            df_comp.sort_values(by=['compname'], ascending=True).compname.unique()
        ]

    tiers_opts = [{'label': i, 'value': i} for i in df_proj.projtier.unique()]
    dists_opts = [{'label': i, 'value': i} for i in df_proj.projverdist.unique()]
    phases_opts = [{'label': i, 'value': i} for i in df_proj.projverphase.unique()]

    return (
        create_alltabs(temp_df_proj, temp_df_comp, temp_df_vuln, temp_df_lic, temp_df_pol,
                       df_projphasepolsec, df_comppolsec, childdata,
                       proj_treemap_color, proj_treemap_size, noprojs, pocserver),
        proj_treemap_color, proj_treemap_size, activetab, pocserver, pocserver, projlist, verlist, complist,
        tiers_opts, dists_opts, phases_opts
    )


@app.callback(
    [
        Output('overviewtab_sankey', 'figure'),
        Output('sankey_state', 'data'),
    ],
    [
        Input('overviewtab_sankey', 'clickData'),
        State('sankey_state', 'data'),
        State('store_pocserver', 'data'),
    ]
)
def callback_overviewtab_sankey(clickdata, state, pocserver):
    print('callback_summarytab_sankey')

    df_main, df_vuln, df_vuln_viz, df_pol, df_pol_viz, df_polmap, df_proj, df_proj_viz, df_comp, df_comp_viz, df_lic, \
        df_lic_viz, df_projcompmap, df_vulnmap, df_vulnactivelist, df_projphasepolsec, childdata, \
        df_comppolsec = get_server_data(pocserver)

    if clickdata is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if state:
        newchilddata = childdata
        newstate = False
    else:
        thisproj = clickdata['points'][0]['label']

        newsources = []
        newtargets = []

        def walktree(srcnum, sources, targets):
            start = 0
            wsources = []
            wtargets = []
            if srcnum in sources[start:]:
                srcidx = sources.index(srcnum, start)
            else:
                srcidx = -1
            while srcidx >= 0:
                tgt = targets[srcidx]
                if tgt in sources:
                    nsrc, ntgt = walktree(tgt, sources, targets)
                    wsources = wsources + nsrc
                    wtargets = wtargets + ntgt
                wsources.append(srcnum)
                wtargets.append(tgt)
                start = srcidx + 1
                if srcnum in sources[start:]:
                    srcidx = sources.index(srcnum, start)
                else:
                    srcidx = -1
            return wsources, wtargets

        if thisproj in childdata['labels']:
            src = childdata['labels'].index(thisproj)
            if src not in childdata['sources']:
                return overviewtab.create_fig_projmap(df_proj, childdata), False

            newsources, newtargets = walktree(src, childdata['sources'], childdata['targets'])

        newchilddata = {
            'labels': childdata['labels'],
            'sources': newsources,
            'targets': newtargets,
            'values': childdata['values'],
        }
        newstate = True

    return overviewtab.create_fig_projmap(df_proj, newchilddata), newstate


@app.callback(
    [
        Output('sel_secrisk', 'value'),
        Output('sel_polsev', 'value'),
        Output('sel_phases', 'value'),
    ],
    [
        Input('overviewtab_comppolsec', 'clickData'),
        Input('overviewtab_projphasepol', 'clickData'),
    ]
)
def callback_overviewtab_compbar(compclick, projclick):
    print('callback_summarytab_sankey')

    if compclick is None and projclick is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    pol = ''
    sec = ''
    phase = ''

    if compclick is not None:
        secs = ['Crit', 'High', 'Med', 'Low', '']

        pol = compclick['points'][0]['x']
        sec = secs[compclick['points'][0]['curveNumber']]

    if projclick is not None:
        path = projclick['points'][0]['id']
        arr = path.split('/')
        if len(arr) > 1:
            phase = arr[1]
        if len(arr) > 2:
            pol = arr[2]
        if len(arr) > 3:
            secvals = {
                'CRITICAL': 'Crit',
                'HIGH': 'High',
                'MEDIUM': 'Med',
                'LOW': 'Low'
            }
            sec = secvals[arr[3]]

    return sec, pol, phase


if __name__ == '__main__':
    app.run_server(host='127.0.0.1', port=8888, debug=False)
