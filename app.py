import json
import sys
import os
from time import time
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

df_main = None
df_vuln = None
df_vuln_viz = None
df_pol = None
df_pol_viz = None
df_pol_map = None
df_proj = None
df_proj_viz = None
df_comp = None
df_comp_viz = None
df_lic = None
df_lic_viz = None
df_projcompmap = None
df_vulnmap = None
df_vulnactivelist = []
lic_compverid_dict = None
compverid_lic_dict = None
df_projphasepolsec = None
df_projdistpol = None
childdata = None
df_comppolsec = None
serverurl = "https://poc11.blackduck.synopsys.com"
dbconfig = 'conf/database.poc11'

expand_child_projects = False

auth = None
lastdbreadtime = 0


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

if __name__ == '__main__':

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

    app.lastdbreadtime = 0
    if os.path.isfile(dbconfig):
        if app.lastdbreadtime:
            if (time() - app.lastdbreadtime) > 3600:
                # Read from DB
                readfrom = 'db'
            else:
                readfrom = 'file'
        else:
            readfrom = 'db'
            app.lastdbreadtime = time()
    elif os.path.isfile('data/db_projs.json') and os.path.isfile('data/db_vulns.json'):
        readfrom = 'file'
    else:
        print('\nNo conf/database.ini or data files - exiting')
        sys.exit(3)

    readfrom = 'file' #DEBUG
    if readfrom == 'db':
        print('\nWill read data from DB connection')
        conn, cur = db.connect(dbconfig)
        print("Getting component data ...")
        df_main = db.get_projdata(conn)
        print("Getting vulnerability data ...")
        df_vuln = db.get_vulndata(conn)
        print("Getting policy data ...")
        df_pol = db.get_poldata(conn)
        db.close_conn(conn, cur)
    elif readfrom == 'file':
        print('\nWill read data from json files')
        df_main, df_vuln, df_pol = read_data_files()

    if df_main is None or len(df_main) == 0 or df_vuln is None or len(df_vuln) == 0 or df_pol is None:
        print("No data obtained from DB or files")
        sys.exit(2)

    if readfrom == 'db':
        print("Writing data to JSON files ...")
        write_data_files(df_main, df_vuln, df_pol)

    df_proj, df_comp, df_projcompmap, childdata = data.proc_comp_data(df_main, serverurl, expand_child_projects)
    df_main = None
    df_comp_viz = df_comp
    # df_proj = data.proc_projdata(df_main)
    df_proj_viz = df_proj
    # print(df_proj)
    df_vuln, df_vulnmap, df_vulnactivelist = data.proc_vuln_data(df_vuln)
    df_vuln_viz = df_vuln
    df_lic, lic_compverid_dict, compverid_lic_dict = data.proc_licdata(df_comp)
    df_lic_viz = df_lic
    df_proj, df_comp, df_pol, df_polmap = data.proc_pol_data(df_proj, df_comp, df_pol)
    df_pol_viz = df_pol
    # data.proc_projinproj(df_proj, df_comp)
    df_projphasepolsec, df_comppolsec = data.proc_overviewdata(df_proj, df_comp)


def create_alltabs(projdata, compdata, vulndata, licdata, poldata, projphasepoldata, comppolsecdata,
                   child_data,
                   colorfield, sizefield, noprojs):

    if noprojs:
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
                            value='seccritcount',
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
                            value='seccritcount',
                            inline=True,
                            # labelStyle={'display': 'inline-block'}
                        ),
                    ],
                    label="Projects Summary",
                    tab_id="tab_projsummary", id="tab_projsummary",
                ),
                dbc.Tab(  # PROJECTS TAB
                    html.H1(children='No Projects Selected by Filters'),
                    label="Projects (0) & Versions (" +
                          str(projdata.projverid.nunique()) + ")",
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
            active_tab="tab_projsummary",
        )

    if projdata is not None:
        projtext = "Projects (" + str(projdata.projname.nunique()) + ") & Versions (" + \
                   str(projdata.projverid.nunique()) + ")"
    else:
        projtext = "Projects (0)"

    if compdata is not None:
        comptext = "Components (" + str(compdata.compname.nunique()) + ")"
    else:
        comptext = "Components(0)"

    if vulndata is not None:
        vulntext = "Vulnerabilties (" + str(len(vulndata)) + ")"
    else:
        vulntext = "Vulnerabilities (0)"

    if licdata is not None:
        lictext = "Licenses (" + str(licdata.licname.nunique()) + ")"
    else:
        lictext = "Licenses (0)"

    if poldata is not None:
        poltext = "Policies (" + str(poldata.polname.nunique()) + ")"
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
        active_tab="tab_overview",
    )


if __name__ == '__main__':
    app.layout = dbc.Container(
        [
            # 		dcc.Store(id='sec_values', storage_type='local'),
            # 		dcc.Store(id='lic_values', storage_type='local'),
            dcc.Store(id='proj_color', storage_type='local'),
            dcc.Store(id='proj_size', storage_type='local'),
            dcc.Store(id='sankey_state', storage_type='local'),
            dbc.NavbarSimple(
                children=[
                    dbc.NavItem(dbc.NavLink("Documentation", href="https://github.com/matthewb66/bddash")),
                ],
                brand="Black Duck Analysis Console",
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
                                {'label': i, 'value': i} for i in
                                df_proj.sort_values(by=['projname'], ascending=True).projname.unique()
                            ], multi=True, placeholder='Select Projects ...'
                        ), width=3,
                        align='center',
                    ),
                    dbc.Col(html.Div(children="Versions"), width=1, align='center'),
                    dbc.Col(
                        dcc.Dropdown(
                            id="sel_versions",
                            options=[
                                {'label': i, 'value': i} for i in
                                df_proj.sort_values(by=['projvername'], ascending=True).projvername.unique()
                            ], multi=True, placeholder='Select Versions ...'
                        ), width=3,
                        align='center',
                    ),
                    dbc.Col(html.Div(children="Components"), width=1, align='center'),
                    dbc.Col(
                        dcc.Dropdown(
                            id="sel_comps",
                            options=[
                                {'label': i, 'value': i} for i in
                                df_comp.sort_values(by=['compname'], ascending=True).compname.unique()
                            ],
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
                                {'label': 'Blocker', 'value': 'BLOCKER'},
                                {'label': 'Critical', 'value': 'CRITICAL'},
                                {'label': 'Major', 'value': 'MAJOR'},
                                {'label': 'Minor', 'value': 'MINOR'},
                                {'label': 'Trivial', 'value': 'TRIVIAL'},
                                {'label': 'Unspec', 'value': 'UNSPECIFIED'},
                            ],
                            multi=True
                        ), width=2,
                        align='center',
                    ),
                    dbc.Col(html.Div(children="Tiers"), width=1, align='center'),
                    dbc.Col(
                        dcc.Dropdown(
                            id="sel_tiers",
                            options=[
                                {'label': i, 'value': i} for i in df_proj.projtier.unique()
                            ],
                            multi=True
                        ), width=2,
                        align='center',
                    ),
                    dbc.Col(html.Div(children="Distribution"), width=1, align='center'),
                    dbc.Col(
                        dcc.Dropdown(
                            id="sel_dists",
                            options=[
                                {'label': i, 'value': i} for i in df_proj.projverdist.unique()
                            ],
                            multi=True
                        ), width=2,
                        align='center',
                    ),
                    dbc.Col(html.Div(children="Phase"), width=1, align='center'),
                    dbc.Col(
                        dcc.Dropdown(
                            id="sel_phases",
                            options=[
                                {'label': i, 'value': i} for i in df_proj.projverphase.unique()
                            ],
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
                    # dbc.Col(
                    #     dbc.Checklist(
                    #         options=[
                    #             {"label": "Ignore Unk Lics", "value": 1},
                    #         ],
                    #         value=[],
                    #         id="sel_ignore_unklic",
                    #         switch=True,
                    #         style={'font-size': '12px'},
                    #     ), width=1,
                    #     align='center',
                    # ),
                ]
            ),
            dbc.Row(html.Hr()),
            dbc.Row(
                dbc.Col(
                    dbc.Spinner(
                        create_alltabs(df_proj, df_comp, df_vuln, df_lic, df_pol, df_projphasepolsec, df_comppolsec,
                                       childdata,
                                       'lichighcountplus1', 'seccritcountplus1', False),
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
    ]

)
def callback_lictab_sellic_button(nclicks, cdata, rows):
    global df_proj_viz, df_comp_viz, df_pol_viz, lic_compverid_dict, df_projcompmap
    print('callback_lictab_sellic_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return lictab.create_lictab_card_lic(df_proj_viz, df_comp_viz, df_projcompmap, lic_compverid_dict,
        #                                      df_lic_viz[df_lic_viz['licname'] == cdata[rows[0]][
        #                                             'licname']])
        return lictab.create_lictab_card_lic(df_proj_viz, df_comp_viz, df_projcompmap, lic_compverid_dict,
                                             cdata[rows[0]])

    return lictab.create_lictab_card_lic(None, None, None, None, None)


@app.callback(
    Output('poltab_card_pol', 'children'),
    [
        Input('sel_pol_button', 'n_clicks'),
        State('poltab_table_pols', 'derived_virtual_data'),
        State('poltab_table_pols', 'derived_virtual_selected_rows'),
    ]

)
def callback_poltab_selpol_button(nclicks, cdata, rows):
    global df_proj_viz, df_comp_viz, df_pol_viz
    print('callback_poltab_selpol_button')

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
    ]

)
def callback_comptab_selcomp_button(nclicks, cdata, rows):
    global df_proj_viz, df_comp_viz, df_projcompmap, df_polmap, df_pol
    print('callback_comptab_selcomp_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # return comptab.create_comptab_card_comp(df_proj_viz, df_projcompmap, df_polmap,
        #                                         df_comp_viz.loc[cdata[rows[0]]['projverid']]), \
        #        'tab_comp_subdetail'
        return comptab.create_comptab_card_comp(df_proj_viz, df_projcompmap, df_pol, df_polmap,
                                                cdata[rows[0]]), 'tab_comp_subdetail'

    return comptab.create_comptab_card_comp(None, None, None, None, None), 'tab_comp_subsummary'


@app.callback(
    Output('vulntab_card_vuln', 'children'),
    [
        Input('sel_vuln_button', 'n_clicks'),
        State('vulntab_table_vulns', 'derived_virtual_data'),
        State('vulntab_table_vulns', 'derived_virtual_selected_rows'),
    ]
)
def callback_vulntab_selvuln_button(nclicks, cdata, rows):
    global df_vuln_viz, df_proj_viz, df_comp_viz, df_vulnmap, df_vulnmap, serverurl
    print('callback_vulntab_selvuln_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        # print(df_vuln[df_vuln['vulnid'] == cdata[rows[0]]['vulnid']].to_string())
        # return vulntab.create_vulntab_card_vuln(df_proj_viz, df_comp_viz, df_vulnmap,
        #                                         df_vuln_viz.loc[cdata[rows[0]]['vulnid']])
        return vulntab.create_vulntab_card_vuln(df_proj_viz, df_comp_viz, df_vulnmap,
                                                cdata[rows[0]], serverurl)

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
    else:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    return [val]


@app.callback(
    Output('sel_comps', 'value'),
    [
        Input('filter_vulncard_comp_button', 'n_clicks'),
        State('vulntab_card_comptable', 'derived_virtual_data'),
        State('vulntab_card_comptable', 'derived_virtual_selected_rows'),
    ]
)
def callback_filtercomp_buttons(nclicks, cdata, rows):
    print('callback_filtercomp_buttons')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    val = ''
    if rows:
        val = cdata[rows[0]]['compname']

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
    ]
)
def callback_projtab_selproj_button(nclicks, cdata, rows):
    global df_proj_viz, df_comp_viz, df_projcompmap, df_polmap, df_pol, serverurl
    print('callback_projtab_selproj_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        projid = cdata[rows[0]]['projverid']
        mydata = df_proj_viz.loc[projid]
        return projtab.create_projtab_card_proj(df_proj_viz, df_comp_viz, df_pol, df_projcompmap, df_polmap,
                                                mydata, serverurl), 'tab_proj_subdetail'

    return projtab.create_projtab_card_proj(None, None, None, None, None, None, None), 'tab_proj_subsummary'


# Update graphs and select options based on selection inputs
@app.callback(
    [
        Output('spinner_main', 'children'),
        Output('proj_color', 'data'),
        Output('proj_size', 'data'),
    ], [
        Input("sel-button", "n_clicks"),
        Input('summtab_color_radio', 'value'),
        Input('summtab_size_radio', 'value'),
        # State("tabs", "active_tab"),
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
    ]
)
def callback_main(nclicks, proj_treemap_color, proj_treemap_size, projs, vers, remstatus,
                  tiers, dists, phases,
                  secrisk, licrisk, polsev, comps, proj_color_prev, proj_size_prev):
    global df_proj, df_proj_viz
    global df_comp, df_projcompmap, df_comp_viz
    global df_vuln, df_vulnmap, df_vulnactivelist, df_vuln_viz
    global df_lic, lic_compverid_dict, compverid_lic_dict, df_lic_viz
    global df_pol, df_pol_viz, df_polmap
    global df_projdistpol, df_projphasepolsec
    global childdata
    print('callback_main')

    # ctx = dash.callback_context
    #
    # changed_id = [p['prop_id'] for p in dash.callback_context.triggered][0]
    # if 'sel-button' not in changed_id and not ctx.triggered and nclicks is None and \
    #         proj_treemap_color == proj_color_prev and \
    #         proj_treemap_size == proj_size_prev:
    #     print('NO ACTION')
    #     raise dash.exceptions.PreventUpdate

    temp_df_proj = df_proj
    temp_df_comp = df_comp
    temp_df_vuln = df_vuln
    temp_df_lic = df_lic
    temp_df_pol = df_pol
    noprojs = False

    # try:
    if True:
        # Process existing select dropdowns
        if projs is not None and len(projs) > 0:
            if isinstance(projs, list):
                temp_df_proj = temp_df_proj[temp_df_proj.projname.isin(projs)]
            else:
                temp_df_proj = temp_df_proj[temp_df_proj['projname'] == projs]

        if vers is not None and len(vers) > 0:
            if isinstance(vers, list):
                temp_df_proj = temp_df_proj[temp_df_proj.projvername.isin(vers)]
            else:
                temp_df_proj = temp_df_proj[temp_df_proj['projname'] == vers]

        if comps is not None and len(comps) > 0:
            # Filter projects based on phase selection
            if isinstance(comps, list):
                temp_df_comp = temp_df_comp[temp_df_comp.compname.isin(comps)]
            else:
                temp_df_comp = temp_df_comp[temp_df_comp['compname'] == comps]

        if dists is not None and len(dists) > 0:
            # Filter projects based on distribution selection
            if isinstance(dists, list):
                temp_df_proj = temp_df_proj[temp_df_proj.projverdist.isin(dists)]
            else:
                temp_df_proj = temp_df_proj[temp_df_proj.projverdist == dists]

        if phases is not None and len(phases) > 0:
            # Filter projects based on phase selection
            if isinstance(phases, list):
                temp_df_proj = temp_df_proj[temp_df_proj.projverphase.isin(phases)]
            else:
                temp_df_proj = temp_df_proj[temp_df_proj.projverphase == phases]

        if remstatus is not None and len(remstatus) > 0:
            # tempvulnidlist = []
            if 'UNREMEDIATED' in remstatus:
                temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(df_vulnactivelist)]
            if 'REMEDIATED' in remstatus:
                temp_df_vuln = temp_df_vuln[~temp_df_vuln.index.isin(df_vulnactivelist)]
            # vulnidlist = pd.merge(vulnidlist, tempvulnidlist, how='inner')

        if secrisk is not None and len(secrisk) > 0:
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

        if licrisk is not None and len(licrisk) > 0:
            # Filter projects based on security risk selection
            temp_df_comp = temp_df_comp[temp_df_comp.lichighcount != '']

            if 'High' in licrisk:
                temp_df_comp = temp_df_comp[temp_df_comp.lichighcount > 0]

            if 'Medium' in licrisk:
                temp_df_comp = temp_df_comp[temp_df_comp.licmedcount > 0]

            if 'Low' in licrisk:
                temp_df_comp = temp_df_comp[temp_df_comp.liclowcount > 0]

        if polsev is not None and len(polsev) > 0:
            # Filter projects based on security risk selection
            for sev in ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'TRIVIAL', 'UNSPECIFIED']:
                if sev in polsev:
                    temp_df_pol = temp_df_pol[temp_df_pol.polseverity == sev]
            comps = df_polmap[df_polmap.polid.isin(temp_df_pol.index.values)].compverid.unique()
            temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(comps)]

        if temp_df_comp is not None and len(temp_df_comp) > 0 and len(temp_df_comp) < len(df_comp):
            temp = df_vulnmap[df_vulnmap.compverid.isin(temp_df_comp.compverid.unique())].index.values
            if len(temp) > 0:
                temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(temp)]
            else:
                temp_df_vuln = None

            temp = df_projcompmap[df_projcompmap.compverid.isin(temp_df_comp.index.values)].index.values
            if len(temp_df_proj) > 0 and len(temp) > 0:
                temp_df_proj = temp_df_proj[temp_df_proj.index.isin(temp)]
            else:
                temp_df_proj = None

            temp = df_polmap[df_polmap.compverid.isin(temp_df_comp.compverid.unique())].polid.unique()
            if len(temp_df_pol) > 0 and len(temp) > 0:
                temp_df_pol = temp_df_pol[temp_df_pol.polid.isin(temp)]
            else:
                temp_df_pol = None

            # temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(compveridlist)]

        elif temp_df_proj is not None and len(temp_df_proj) > 0 and len(temp_df_proj) < len(df_proj):
            temp = df_projcompmap[df_projcompmap.index.isin(temp_df_proj.index.values)].compverid.unique()
            if len(temp) > 0:
                temp_df_comp = temp_df_comp[temp_df_comp.compverid.isin(temp)]
            else:
                temp_df_comp = None

            temp = df_vulnmap[df_vulnmap.projverid.isin(temp_df_proj.index.values)].index.values
            if len(temp) > 0:
                temp_df_vuln = temp_df_vuln[temp_df_vuln.index.isin(temp)]
            else:
                temp_df_vuln = None

            temp = df_polmap[df_polmap.projverid.isin(temp_df_proj.index.values)].polid.unique()
            if len(temp_df_pol) > 0 and len(temp) > 0:
                temp_df_pol = temp_df_pol[temp_df_pol.polid.isin(temp)]
            else:
                temp_df_pol = None

            # temp_df_proj = temp_df_proj[temp_df_proj.projverid.isin(projveridlist)]

        if temp_df_comp is not None and len(temp_df_comp) > 0 and len(temp_df_comp) < len(df_comp):
            licnames = []
            for cid in temp_df_comp.compverid.unique():
                if cid in compverid_lic_dict.keys():
                    [licnames.append(x) for x in compverid_lic_dict[cid] if x not in licnames]
            licnames.sort()
            temp_df_lic = temp_df_lic[temp_df_lic.licname.isin(licnames)]

    # except Exception as e:
    #     print('Exception:')
    #     print(e)
    #     noprojs = True

    if temp_df_proj is None or len(temp_df_proj) == 0 or \
            temp_df_comp is None or len(temp_df_comp) == 0:
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

    df_proj_viz = temp_df_proj
    df_comp_viz = temp_df_comp
    df_vuln_viz = temp_df_vuln
    df_lic_viz = temp_df_lic
    df_pol_viz = temp_df_pol
    return (
        create_alltabs(temp_df_proj, temp_df_comp, temp_df_vuln, temp_df_lic, temp_df_pol,
                       df_projphasepolsec, df_comppolsec, childdata,
                       proj_treemap_color, proj_treemap_size, noprojs),
        proj_treemap_color, proj_treemap_size,
    )


@app.callback(
    [
        Output('summarytab_sankey', 'figure'),
        Output('sankey_state', 'data'),
    ],
    [
        Input('summarytab_sankey', 'clickData'),
        State('sankey_state', 'data'),
    ]
)
def callback_summarytab_sankey(clickData, state):
    global childdata, df_proj

    print('callback_summarytab_sankey')

    if clickData is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if state:
        newchilddata = childdata
        newstate = False
    else:
        thisproj = clickData['points'][0]['label']

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
            newsources, newtargets = walktree(src, childdata['sources'], childdata['targets'])

        newchilddata = {
            'labels': childdata['labels'],
            'sources': newsources,
            'targets': newtargets,
            'values': childdata['values'],
        }
        newstate = True

    return overviewtab.create_fig_projmap(df_proj, newchilddata), newstate


if __name__ == '__main__':
    app.run_server(debug=True)
