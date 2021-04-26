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

import dash_auth
import db
import data
import lictab
import vulntab
import comptab
import projtab
import projsumm
import poltab
import overviewtab

df_main = {}
df_vuln = {}
df_vuln_viz = {}
df_pol = {}
df_pol_viz = {}
df_polmap = {}
df_proj = {}
df_proj_viz = {}
df_comp = {}
df_comp_viz = {}
df_lic = {}
df_lic_viz = {}
df_projcompmap = {}
df_vulnmap = {}
df_vulnactivelist = {}
# lic_compverid_dict = None
# compverid_lic_dict = None
df_projphasepolsec = {}
df_projdistpol = {}
childdata = {}
df_comppolsec = {}

init = {}

serverlist = []
serverurl = {}

projlist = {}
verlist = {}
complist = {}

expand_child_projects = False

auth = None
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


def write_data_files(maindf, vulndf, poldf):
    # from app import df_main, df_vuln
    jsonout = maindf.to_json(orient="split")
    o = open("data/db_projs.json", "w")
    o.write(json.dumps(jsonout, indent=4))
    o.close()

    jsonout = vulndf.to_json(orient="split")
    o = open("data/db_vulns.json", "w")
    o.write(json.dumps(jsonout, indent=4))
    o.close()

    jsonout = poldf.to_json(orient="split")
    o = open("data/db_pols.json", "w")
    o.write(json.dumps(jsonout, indent=4))
    o.close()
    print("Done\n")


app = dash.Dash(external_stylesheets=[dbc.themes.COSMO])

server = app.server


if not os.path.isfile('conf/users.txt'):
    print('No users.txt file - exiting')
    sys.exit(3)

with open('conf/users.txt') as f:
    fdata = f.read()
    VALID_USERNAME_PASSWORD_PAIRS = json.loads(fdata)
    f.close()

# app = dash.Dash(external_stylesheets=[dbc.themes.COSMO])
app.auth = dash_auth.BasicAuth(
    app,
    VALID_USERNAME_PASSWORD_PAIRS
)


def get_server_data(pocserver):
    global df_main
    global df_vuln
    global df_vuln_viz
    global df_pol
    global df_pol_viz
    global df_polmap
    global df_proj
    global df_proj_viz
    global df_comp
    global df_comp_viz
    global df_lic
    global df_lic_viz
    global df_projcompmap
    global df_vulnmap
    global df_vulnactivelist
    global df_projphasepolsec
    global df_projdistpol
    global childdata
    global df_comppolsec
    global init
    global serverlist

    serverurl[pocserver] = 'https://' + pocserver + '.blackduck.synopsys.com'
    dbconfig = 'conf/database.' + pocserver
    
    serverlist.append(pocserver)
    
    app.lastdbreadtime = 0
    if os.path.isfile(dbconfig):
        # if app.lastdbreadtime:
        #     if (time() - app.lastdbreadtime) > 3600:
        #         # Read from DB
        #         readfrom = 'db'
        #     # else:
        #     #     readfrom = 'file'
        # else:
        readfrom = 'db'
        # app.lastdbreadtime = time()
    # elif os.path.isfile('data/db_projs.json') and os.path.isfile('data/db_vulns.json'):
    #     readfrom = 'file'
    else:
        print('\nNo conf/database.ini or data files - exiting')
        sys.exit(3)
    
    # readfrom = 'file'  # DEBUG
    statusitem = ''
    if readfrom == 'db':
        print('\nWill read data from DB connection')
        conn, cur = db.connect(dbconfig)
        print("Getting component data ...")
        df_main[pocserver] = db.get_projdata(conn)
        print("Getting vulnerability data ...")
        df_vuln[pocserver] = db.get_vulndata(conn)
        print("Getting policy data ...")
        df_pol[pocserver] = db.get_poldata(conn)
        db.close_conn(conn, cur)
    # elif readfrom == 'file':
    #     print('\nWill read data from json files')
    #     df_main, df_vuln, df_pol = read_data_files()
    #     statusitem = dbc.NavItem(dbc.NavLink("Status: Data from Files", href='#', disabled=True))
    
    if isempty(df_main[pocserver]) or isempty(df_vuln[pocserver]) or isempty(df_pol[pocserver]):
        print("No data obtained from DB")
        sys.exit(2)
    
    # if readfrom == 'db':
    #     print("Writing data to JSON files ...")
    #     write_data_files(df_main, df_vuln, df_pol)
    
    df_proj[pocserver], df_comp[pocserver], df_projcompmap[pocserver], childdata[pocserver] = \
        data.proc_comp_data(df_main[pocserver], expand_child_projects)
    df_main[pocserver] = None
    df_comp_viz[pocserver] = df_comp
    # df_proj = data.proc_projdata(df_main)
    df_proj_viz[pocserver] = df_proj
    # print(df_proj)
    df_vuln[pocserver], df_vulnmap[pocserver], df_vulnactivelist[pocserver] = \
        data.proc_vuln_data(df_vuln[pocserver])
    df_vuln_viz[pocserver] = df_vuln[pocserver]
    df_lic[pocserver] = data.proc_licdata(df_comp[pocserver])
    df_lic_viz[pocserver] = df_lic[pocserver]
    df_proj[pocserver], df_comp[pocserver], df_pol[pocserver], df_polmap[pocserver] = \
        data.proc_pol_data(df_proj[pocserver], df_comp[pocserver], df_pol[pocserver])
    df_pol_viz[pocserver] = df_pol[pocserver]
    # data.proc_projinproj(df_proj, df_comp)
    df_projphasepolsec[pocserver], df_comppolsec[pocserver] = \
        data.proc_overviewdata(df_proj[pocserver], df_comp[pocserver])

    projlist[pocserver] = [
            {'label': i, 'value': i} for i in
            df_proj[pocserver].sort_values(by=['projname'], ascending=True).projname.unique()
        ]
    
    verlist[pocserver] = [
            {'label': i, 'value': i} for i in
            df_proj[pocserver].sort_values(by=['projvername'], ascending=True).projvername.unique()
        ]
    
    complist[pocserver] = [
            {'label': i, 'value': i} for i in
            df_comp[pocserver].sort_values(by=['compname'], ascending=True).compname.unique()
        ]


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

    if isempty(projdata):
        projtext = "Projects (" + str(projdata.projid.nunique()) + ") & Versions (" + \
                   str(projdata.projverid.nunique()) + ")"
    else:
        projtext = "Projects (0)"

    if isempty(compdata):
        comptext = "Components (" + str(compdata.compverid.nunique()) + ")"
    else:
        comptext = "Components(0)"

    if isempty(vulndata):
        vulntext = "Vulnerabilties (" + str(len(vulndata)) + ")"
    else:
        vulntext = "Vulnerabilities (0)"

    if isempty(licdata):
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
        dcc.Location(id='thispath', refresh=False),
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
    global df_proj_viz, df_comp_viz, df_pol_viz, df_projcompmap
    print('callback_lictab_sellic_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return lictab.create_lictab_card_lic(df_proj_viz, df_comp_viz, df_projcompmap, lic_compverid_dict,
        #                                      df_lic_viz[df_lic_viz['licname'] == cdata[rows[0]][
        #                                             'licname']])
        return lictab.create_lictab_card_lic(df_proj_viz[pocserver], df_comp_viz[pocserver], df_projcompmap[pocserver],
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
    global df_proj_viz, df_comp_viz, df_pol_viz
    print('callback_poltab_selpol_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return poltab.create_poltab_card_pol(df_proj_viz, df_comp_viz, df_pol,
        #                                      df_pol_viz.loc[cdata[rows[0]]])
        return poltab.create_poltab_card_pol(df_proj_viz[pocserver], df_comp_viz[pocserver], df_pol[pocserver],
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
    global df_proj_viz, df_comp_viz, df_projcompmap, df_polmap, df_pol
    print('callback_comptab_selcomp_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return comptab.create_comptab_card_comp(df_proj_viz, df_projcompmap, df_polmap,
        #                                         df_comp_viz.loc[cdata[rows[0]]['projverid']]), \
        #        'tab_comp_subdetail'
        return comptab.create_comptab_card_comp(df_proj_viz[pocserver], df_projcompmap[pocserver], df_pol[pocserver],
                                                df_polmap[pocserver],
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
    global df_vuln_viz, df_proj_viz, df_comp_viz, df_vulnmap, df_vulnmap, serverurl
    print('callback_vulntab_selvuln_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # print(df_vuln[df_vuln['vulnid'] == cdata[rows[0]]['vulnid']].to_string())
        # return vulntab.create_vulntab_card_vuln(df_proj_viz, df_comp_viz, df_vulnmap,
        #                                         df_vuln_viz.loc[cdata[rows[0]]['vulnid']])
        return vulntab.create_vulntab_card_vuln(df_proj_viz[pocserver], df_comp_viz[pocserver], df_vulnmap[pocserver],
                                                cdata[rows[0]], serverurl[pocserver])

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
    # print(projdata)

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
    global df_proj_viz, df_comp_viz, df_projcompmap, df_polmap, df_pol, serverurl
    print('callback_projtab_selproj_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        projid = cdata[rows[0]]['projverid']
        mydata = df_proj_viz[pocserver].loc[projid]
        return projtab.create_projtab_card_proj(df_proj_viz[pocserver], df_comp_viz[pocserver], df_pol[pocserver],
                                                df_projcompmap[pocserver], df_polmap[pocserver],
                                                mydata, serverurl[pocserver]), 'tab_proj_subdetail'

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
    global df_proj, df_proj_viz
    global df_comp, df_projcompmap, df_comp_viz
    global df_vuln, df_vulnmap, df_vulnactivelist, df_vuln_viz
    global df_lic, df_lic_viz
    global df_pol, df_pol_viz, df_polmap
    global df_projdistpol, df_projphasepolsec
    global childdata
    global init
    global serverlist
    
    print('callback_main')

    if pocserver is None or pocserver == '':
        if path is not None and path != '':
            pocserver = str(path).replace('/', '')
        else:
            print("NO ACTION")
            raise dash.exceptions.PreventUpdate

    if pocserver is not None and pocserver not in serverlist:
        get_server_data(pocserver)

    # ctx = dash.callback_context
    #
    # changed_id = [p['prop_id'] for p in dash.callback_context.triggered][0]
    # if 'sel-button' not in changed_id and not ctx.triggered and nclicks is None and \
    #         proj_treemap_color == proj_color_prev and \
    #         proj_treemap_size == proj_size_prev:
    #     print('NO ACTION')
    #     raise dash.exceptions.PreventUpdate

    temp_df_proj = df_proj[pocserver]
    temp_df_comp = df_comp[pocserver]
    temp_df_vuln = df_vuln[pocserver]
    temp_df_lic = df_lic[pocserver]
    temp_df_pol = df_pol[pocserver]
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
    if (not isempty(temp_df_proj)) and len(temp_df_proj) < len(df_proj[pocserver]):
        projcompmap = df_projcompmap[pocserver]
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
        polmap = df_polmap[pocserver]
        comps = polmap[polmap.polid.isin(temp_df_pol.index.values)].compverid.unique()
        temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(comps)]

    if (not isempty(temp_df_comp)) and 0 < len(temp_df_comp) < len(df_comp[pocserver]):
        vulnmap = df_vulnmap[pocserver]
        temp = vulnmap[vulnmap.compverid.isin(temp_df_comp.compverid.unique())].index.values
        if not isempty(temp):
            temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(temp)]
        else:
            temp_df_vuln = None

        projcompmap = df_projcompmap[pocserver]
        temp = projcompmap[projcompmap.compverid.isin(temp_df_comp.index.values)].index.values
        if (not isempty(temp_df_proj)) and (not isempty(temp)):
            temp_df_proj = temp_df_proj[temp_df_proj.index.isin(temp)]
        else:
            temp_df_proj = None

        polmap = df_polmap[pocserver]
        temp = polmap[polmap.compverid.isin(temp_df_comp.compverid.unique())].polid.unique()
        if (not isempty(temp_df_pol)) and (not isempty(temp)):
            temp_df_pol = temp_df_pol[temp_df_pol.polid.isin(temp)]
        else:
            temp_df_pol = None

        # temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(compveridlist)]

    elif (not isempty(temp_df_proj)) and 0 < len(temp_df_proj) < len(df_proj[pocserver]):
        projcompmap = df_projcompmap[pocserver]
        temp = projcompmap[projcompmap.index.isin(temp_df_proj.index.values)].compverid.unique()
        if not isempty(temp):
            temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(temp)]
        else:
            temp_df_comp = None

        vulnmap = df_vulnmap[pocserver]
        temp = vulnmap[vulnmap.projverid.isin(temp_df_proj.index.values)].index.values
        if not isempty(temp):
            temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(temp)]
        else:
            temp_df_vuln = None

        polmap = df_polmap[pocserver]
        temp = polmap[polmap.projverid.isin(temp_df_proj.index.values)].polid.unique()
        if (not isempty(temp_df_pol)) and (not isempty(temp)):
            temp_df_pol = temp_df_pol[temp_df_pol.polid.isin(temp)]
        else:
            temp_df_pol = None

        # temp_df_proj = temp_df_proj[temp_df_proj.projverid.isin(projveridlist)]

    if (not isempty(temp_df_comp)) and 0 < len(temp_df_comp) < len(df_comp[pocserver]):
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
            temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(df_vulnactivelist[pocserver])]
        if {'REMEDIATED'}.intersection(set(remstatus)) == {'REMEDIATED'}:
            temp_df_vuln = temp_df_vuln[~temp_df_vuln.index.isin(df_vulnactivelist[pocserver])]
        # vulnidlist = pd.merge(vulnidlist, tempvulnidlist, how='inner')

    if isempty(temp_df_proj) or isempty(temp_df_comp):
        noprojs = True

    # # Click on projtab_treemap
    # if click_proj['points'][0]['parent'] == '':
    #     # All
    #     pass
    # elif click_proj['points'][0]['parent'] == 'All':
    #     # Project
    #     temp_df_proj = temp_df_proj[temp_df_proj.projname == click_proj['points'][0]['label']]
    # else:
    #     # ProjectVersion
    #     temp_df_proj = temp_df_proj[(temp_df_proj.projname == click_proj['points'][0]['parent']) &
    #                                 (temp_df_proj.projvername == click_proj['points'][0]['label'])]
    #

    df_proj_viz[pocserver] = temp_df_proj
    df_comp_viz[pocserver] = temp_df_comp
    df_vuln_viz[pocserver] = temp_df_vuln
    df_lic_viz[pocserver] = temp_df_lic
    df_pol_viz[pocserver] = temp_df_pol

    # if not (proj_treemap_size == proj_size_prev and proj_treemap_color == proj_color_prev):
    #     activetab = 'tab_projsummary'
    # elif activetab is None or activetab == '':
    #     activetab = 'tab_overview'
    if init:
        activetab = 'tab_overview'
        init[pocserver] = False
    else:
        activetab = tab

    tiers_opts = [{'label': i, 'value': i} for i in df_proj[pocserver].projtier.unique()]
    dists_opts = [{'label': i, 'value': i} for i in df_proj[pocserver].projverdist.unique()]
    phases_opts = [{'label': i, 'value': i} for i in df_proj[pocserver].projverphase.unique()]

    return (
        create_alltabs(temp_df_proj, temp_df_comp, temp_df_vuln, temp_df_lic, temp_df_pol,
                       df_projphasepolsec[pocserver], df_comppolsec[pocserver], childdata[pocserver],
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
    global childdata, df_proj

    print('callback_summarytab_sankey')

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
                return overviewtab.create_fig_projmap(df_proj[pocserver], childdata[pocserver]), False

            newsources, newtargets = walktree(src, childdata[pocserver]['sources'], childdata[pocserver]['targets'])

        newchilddata = {
            'labels': childdata[pocserver]['labels'],
            'sources': newsources,
            'targets': newtargets,
            'values': childdata[pocserver]['values'],
        }
        newstate = True

    return overviewtab.create_fig_projmap(df_proj[pocserver], newchilddata), newstate


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


# @app.callback(
#     [
#         Output('poc_server', 'children'),
#         Output('store_pocserver', 'data'),
#         Output('sel_projects', 'options'),
#         Output('sel_versions', 'options'),
#         Output('sel_comps', 'options'),
#         Output('sel_tiers', 'options'),
#         Output('sel_dists', 'options'),
#         Output('sel_phases', 'options'),
#     ],
#     [
#         Input('thispath', 'pathname')
#     ]
# )
# def cb_url_pocserver(pathname):
#     if pathname is None or len(pathname) < 1:
#         print("NO ACTION")
#         raise dash.exceptions.PreventUpdate
#
#     print("callback_pocserver")
#     pname = str(pathname).replace('/', '').upper()
#     print(pname)
#     tiers = [{'label': i, 'value': i} for i in df_proj[pname].projtier.unique()]
#     dists = [{'label': i, 'value': i} for i in df_proj[pname].projverdist.unique()]
#     phases = [{'label': i, 'value': i} for i in df_proj[pname].projverphase.unique()]
#
#     return pname, pname, projlist[pname], verlist[pname], complist[pname], tiers, dists, phases


# if __name__ == '__main__':
#    app.run_server(debug=True)

if __name__ == '__main__':
    app.run_server(host='127.0.0.1', port=8888, debug=False)
