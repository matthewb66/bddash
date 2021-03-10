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


df_main = None
df_vuln = None
df_proj = None
df_comp = None
df_projcompmap = None
df_projvulnmap = None
df_compvulnmap = None
df_lic = None
lic_compverid_dict = None
compverid_lic_dict = None
auth = None
lastdbreadtime = 0



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
    jsonout = df_main.to_json(orient="split")
    o = open("db_projs.json", "w")
    o.write(json.dumps(jsonout, indent=4))
    o.close()
    jsonout = df_vuln.to_json(orient="split")
    o = open("db_vulns.json", "w")
    o.write(json.dumps(jsonout, indent=4))
    o.close()

app = dash.Dash(external_stylesheets=[dbc.themes.COSMO])
if __name__ == '__main__':

    server = app.server

    if not os.path.isfile('users.txt'):
        print('No users.txt file - exiting')
        sys.exit(3)

    with open('users.txt') as f:
        fdata = f.read()
        VALID_USERNAME_PASSWORD_PAIRS = json.loads(fdata)
        f.close()

    # app = dash.Dash(external_stylesheets=[dbc.themes.COSMO])
    app.auth = dash_auth.BasicAuth(
        app,
        VALID_USERNAME_PASSWORD_PAIRS
    )

    app.lastdbreadtime = 0
    if os.path.isfile('database.ini'):
        if app.lastdbreadtime:
            if (time() - app.lastdbreadtime) > 3600:
                # Read from DB
                readfrom = 'db'
            else:
                readfrom = 'file'
        else:
            readfrom = 'db'
            app.lastdbreadtime = time()
    elif os.path.isfile('db_projs.json') and os.path.isfile('db_vulns.json'):
        readfrom = 'file'
    else:
        print('\nNo database.ini or data files - exiting')
        sys.exit(3)

    if readfrom == 'db':
        print('\nWill read data from DB connection')
        conn, cur = db.connect()
        print("Getting project data ...")
        df_main = db.get_projdata(cur)
        print("Getting vulnerability data ...")
        df_vuln = db.get_vulndata(cur)
        db.close_conn(conn, cur)
    elif readfrom == 'file':
        print('\nWill read data from json files')
        df_main, df_vuln = read_data_files()

    if df_main is None or df_main.size == 0:
        print("No data obtained from DB or files")
        sys.exit(2)

    if readfrom == 'db':
        print("Writing data to JSON files ...")
        write_data_files()

    df_proj = data.proc_projdata(df_main)
    print(df_proj)
    df_comp, df_projcompmap = data.proc_comp_data(df_main)
    df_vuln, df_projvulnmap, df_compvulnmap = data.proc_vuln_data(df_vuln)
    df_lic, lic_compverid_dict, compverid_lic_dict = data.proc_licdata(df_comp)


def create_alltabs(projdata, compdata, vulndata, licdata, colorfield, sizefield, noprojs):
    if noprojs:
        return dbc.Tabs(
            [
                dbc.Tab(  # SUMMARY TAB
                    [
                        html.H1(children='No Projects Selected by Filters'),
                        dbc.RadioItems(
                            options=[
                                # {'label': 'Critical Vulns', 'value': 'secCritCount'},
                                # {'label': 'High Vulns', 'value': 'secHighCount'},
                                # {'label': 'High Licenses', 'value': 'licHighCount'},
                            ],
                            id='summtab_color_radio',
                            value='secCritCount',
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
                          str(projdata.projVerId.nunique()) + ")",
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

    return dbc.Tabs(
        [
            dbc.Tab(  # SUMMARY TAB
                projsumm.create_projsummtab(projdata, colorfield, sizefield), label="Projects Summary",
                tab_id="tab_projsummary", id="tab_projsummary",
            ),
            dbc.Tab(  # PROJECTS TAB
                projtab.create_projtab(projdata),
                label="Projects (" + str(projdata.projName.nunique()) + ") & Versions (" +
                      str(projdata.projVerId.nunique()) + ")",
                tab_id="tab_projects", id="tab_projects"
            ),
            dbc.Tab(  # COMPONENTS TAB
                comptab.create_comptab(compdata),
                label="Components (" + str(compdata.compName.nunique()) + ")",
                tab_id="tab_components", id="tab_components"
            ),
            dbc.Tab(  # VULNS TAB
                vulntab.create_vulntab(vulndata),
                label="Vulnerabilties (" + str(vulndata.vulnId.nunique()) + ")",
                tab_id="tab_vulns", id="tab_vulns"
            ),
            dbc.Tab(  # LICENSE TAB
                lictab.create_lictab(licdata),
                label="Licenses (" + str(licdata.licName.nunique()) + ")",
                # label="Licenses",
                tab_id="tab_lics", id="tab_lics"
            )
        ],
        id="tabs",
        active_tab="tab_projsummary",
    )


if __name__ == '__main__':
    app.layout = dbc.Container(
        [
            # 		dcc.Store(id='sec_values', storage_type='local'),
            # 		dcc.Store(id='lic_values', storage_type='local'),
            dcc.Store(id='proj_color', storage_type='local'),
            dcc.Store(id='proj_size', storage_type='local'),
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
                                {'label': i, 'value': i} for i in
                                df_proj.sort_values(by=['projName'], ascending=True).projName.unique()
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
                                df_proj.sort_values(by=['projVerName'], ascending=True).projVerName.unique()
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
                                df_comp.sort_values(by=['compName'], ascending=True).compName.unique()
                            ],
                            multi=True
                        ), width=3,
                        align='center',
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(html.Div(children="Vuln Remediation Status"), width=1, align='center', style={'font-size': '12px'},),
                    dbc.Col(
                        dcc.Dropdown(
                            id="sel_remstatus",
                            options=[
                                {'label': 'New', 'value': 'NEW'},
                                {'label': 'NeedsRev', 'value': 'NEEDS_REVIEW'},
                                {'label': 'Patched', 'value': 'PATCHED'},
                                {'label': 'RemReq', 'value': 'REMEDIATION_REQUIRED'},
                                {'label': 'Remdtd', 'value': 'REMEDIATED'},
                                {'label': 'Ignored', 'value': 'IGNORED'},
                            ],
                            value=['NEW', 'NEEDS_REVIEW', 'REMEDIATION_REQUIRED'],
                            multi=True
                        ), width=3,
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
                        ), width=3,
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
                        ), width=3,
                        align='center',
                    ),
                    dbc.Col(html.Div(children="Tiers"), width=1, align='center'),
                    dbc.Col(
                        dcc.Dropdown(
                            id="sel_tiers",
                            options=[
                                {'label': i, 'value': i} for i in df_proj.projTier.unique()
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
                                {'label': i, 'value': i} for i in df_proj.projVerDist.unique()
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
                                {'label': i, 'value': i} for i in df_proj.projVerPhase.unique()
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
                        create_alltabs(df_proj, df_comp, df_vuln, df_lic, 'secCritCountplus1', 'compCount', False),
                        id='spinner_main',
                    ), width=12,
                )
            ),
        ], fluid=True
    )





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
    global df_proj
    print('callback_comptab_selcomp_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        return comptab.create_comptab_card_comp(df_comp, df_projcompmap,
            df_comp[df_comp['compVerId'] == cdata[rows[0]]['compVerId']]), 'tab_comp_subdetail'

    return comptab.create_comptab_card_comp(None, None, None), 'tab_comp_subsummary'


@app.callback(
    Output('vulntab_card_vuln', 'children'),
    [
        Input('sel_vuln_button', 'n_clicks'),
        State('vulntab_table_vulns', 'derived_virtual_data'),
        State('vulntab_table_vulns', 'derived_virtual_selected_rows'),
    ]
)
def callback_vulntab_selvuln_button(nclicks, cdata, rows):
    global df_vuln
    print('callback_vulntab_selvuln_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        print(df_vuln[df_vuln['vulnId'] == cdata[rows[0]]['vulnId']].to_string())
        return vulntab.create_vulntab_card_vuln(df_proj, df_comp, df_projvulnmap, df_compvulnmap,
                                                df_vuln[df_vuln['vulnId'] == cdata[rows[0]]['vulnId']])

    return vulntab.create_vulntab_card_vuln(None, None, None, None, None)


@app.callback(
    [
        Output('sel_projects', 'value'),
        # Output('sel_versions', 'value'),
    ],
    [
        Input('filter_compcard_proj_button', 'n_clicks'),
        Input('filter_vulncard_proj_button', 'n_clicks'),
        Input('filter_thisproj_button', 'n_clicks'),
        Input('filter_usedproj_button', 'n_clicks'),
        State('comptab_card_projtable', 'derived_virtual_data'),
        State('comptab_card_projtable', 'derived_virtual_selected_rows'),
        State('vulntab_card_projtable', 'derived_virtual_data'),
        State('vulntab_card_projtable', 'derived_virtual_selected_rows'),
        State('projtab_table_projs', 'derived_virtual_data'),
        State('projtab_table_projs', 'derived_virtual_selected_rows'),
        State('projtab_detail_projtable', 'derived_virtual_data'),
        State('projtab_detail_projtable', 'derived_virtual_selected_rows'),
    ]
)
def callback_filterproj_buttons(compprojclicks, vulnprojclicks, projclicks, usedprojclicks,
                                compprojdata, compprojrows, vulnprojdata, vulnprojrows,
                                projdata, projrows, projuseddata, projusedrows):
    print('callback_filterproj_buttons')
    # print(projdata)

    changed_id = [p['prop_id'] for p in dash.callback_context.triggered][0]

    if compprojdata is not None and 'filter_compcard_proj_button' in changed_id and len(compprojrows) > 0:
        val = compprojdata[compprojrows[0]]['projName']
    elif vulnprojdata is not None and 'filter_vulncard_proj_button' in changed_id and len(vulnprojrows) > 0:
        val = vulnprojdata[vulnprojrows[0]]['projName']
    elif projdata is not None and 'filter_thisproj_button' in changed_id and len(projrows) > 0:
        val = projdata[projrows[0]]['projName']
    elif projuseddata is not None and 'filter_usedproj_button' in changed_id and len(projusedrows) > 0:
        val = projuseddata[projusedrows[0]]['projName']
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
        val = cdata[rows[0]]['compName']

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
    global df_proj, df_comp, df_projcompmap
    print('callback_projtab_selproj_button')

    if nclicks is None:
        print('NO ACTION')
        raise dash.exceptions.PreventUpdate

    if rows:
        return projtab.create_projtab_card_proj(df_proj, df_comp, df_projcompmap,
            df_proj[df_proj['projVerId'] == cdata[rows[0]]['projVerId']]), 'tab_proj_subdetail'

    return projtab.create_projtab_card_proj(None, None, None, None), 'tab_proj_subsummary'


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
        # State('sel_ignore_unklic', 'value'),
        State('sel_comps', 'value'),
        State('proj_color', 'data'),
        State('proj_size', 'data'),
    ]
)
def callback_main(nclicks, proj_treemap_color, proj_treemap_size, projs, vers, remstatus,
                  tiers, dists, phases,
                  secrisk, licrisk, comps, proj_color_prev, proj_size_prev):
    global df_proj
    global df_comp, df_projcompmap
    global df_vuln, df_projvulnmap, df_compvulnmap
    global df_lic, lic_compverid_dict, compverid_lic_dict
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
    noprojs = False
    recalc = False

    try:
        # Process existing select dropdowns
        if projs is not None and len(projs) > 0:
            if isinstance(projs, list):
                # Filter projects from selection
                temp_df_proj = temp_df_proj[temp_df_proj.projName.isin(projs)]
            else:
                temp_df_proj = temp_df_proj[temp_df_proj['projName'] == projs]

            # Set project version dropdowns
            sel_vers_options = [{'label': i, 'value': i} for i in temp_df_proj.projVerName.unique()]
            recalc = True
        else:
            # Version selection only possible if Project selected
            sel_vers_options = []

        if vers is not None and len(vers) > 0:
            if isinstance(vers, list):
                # Filter versions from selection
                temp_df_proj = temp_df_proj[temp_df_proj.projVerName.isin(vers)]
            else:
                temp_df_proj = temp_df_proj[temp_df_proj['projName'] == vers]

            recalc = True

        if comps is not None and len(comps) > 0:
            # Filter projects based on phase selection

            if isinstance(comps, list):
                temp_df_comp = temp_df_comp[temp_df_comp.compName.isin(comps)]
            else:
                temp_df_comp = temp_df_comp[temp_df_comp['compName'] == comps]

            compverids = temp_df_comp['compVerId'].unique()
            projverids = df_projcompmap[df_projcompmap.compVerId.isin(compverids)]['projVerId'].unique()
            temp_df_proj = temp_df_proj[temp_df_proj.projVerId.isin(projverids)]

            vulnids = df_compvulnmap[df_compvulnmap.compVerId.isin(compverids)]['vulnId'].unique()
            temp_df_vuln = temp_df_vuln[temp_df_vuln.vulnId.isin(vulnids)]
            # recalc = True

        # Modify dropdown options
        # sel_tiers_options = [{'label': i, 'value': i} for i in temp_df_proj.projTier.unique()]
        # sel_dists_options = [{'label': i, 'value': i} for i in temp_df_proj.projVerDist.unique()]
        # sel_phases_options = [{'label': i, 'value': i} for i in temp_df_proj.projVerPhase.unique()]
        # sel_comps_options = [{'label': i, 'value': i} for i in temp_df_comp.compName.sort_values().unique()]

        if dists is not None and len(dists) > 0 and len(temp_df_proj) > 0:
            # Filter projects based on distribution selection
            temp_df_proj = temp_df_proj[temp_df_proj.projVerDist.isin(dists)]
            recalc = True
        if phases is not None and len(phases) > 0 and len(temp_df_proj) > 0:
            # Filter projects based on phase selection
            temp_df_proj = temp_df_proj[temp_df_proj.projVerPhase.isin(phases)]
            recalc = True

        if projs is not None and len(projs) > 0:
            if isinstance(projs, list):
                # Filter projects from selection
                temp_df_proj = temp_df_proj[temp_df_proj.projName.isin(projs)]
            else:
                temp_df_proj = temp_df_proj[temp_df_proj['projName'] == projs]

            # Set project version dropdowns
            # sel_vers_options = [{'label': i, 'value': i} for i in temp_df_proj.projVerName.unique()]
            recalc = True
        # else:
        #     # Version selection only possible if Project selected
        #     sel_vers_options = []

        if recalc and len(temp_df_proj) > 0:
            # Filter components based on projcompmap
            projverids = temp_df_proj['projVerId'].unique()

            compverids = df_projcompmap[df_projcompmap.projVerId.isin(projverids)]['compVerId'].unique()

            temp_df_comp = temp_df_comp[temp_df_comp.compVerId.isin(compverids)]

            # Filter vulns based on projvulnmap
            vulnids = df_projvulnmap[df_projvulnmap.projVerId.isin(projverids)]['vulnId'].unique()
            temp_df_vuln = temp_df_vuln[temp_df_vuln.vulnId.isin(vulnids)]

            licnames = []
            for cid in compverids:
                if cid in compverid_lic_dict.keys():
                    [licnames.append(x) for x in compverid_lic_dict[cid] if x not in licnames]
            licnames.sort()
            temp_df_lic = temp_df_lic[temp_df_lic.licName.isin(licnames)]

        if remstatus is not None and len(remstatus) > 0:
            # Filter projects based on remstatus selection
            if isinstance(remstatus, list):
                temp_df_vuln = temp_df_vuln[temp_df_vuln.remStatus.isin(remstatus)]
            else:
                temp_df_vuln = temp_df_vuln[temp_df_vuln['remStatus'] == remstatus]

            vulnids = temp_df_vuln.vulnId.unique()
            projids = df_projvulnmap[df_projvulnmap.vulnId.isin(vulnids)]['projVerId'].unique()
            temp_df_proj = temp_df_proj[temp_df_proj['projVerId'].isin(projids)]
            compids = df_compvulnmap[df_compvulnmap.vulnId.isin(vulnids)]['compVerId'].unique()
            temp_df_comp = temp_df_comp[temp_df_comp['compVerId'].isin(compids)]

        if secrisk is not None and len(secrisk) > 0 and len(temp_df_proj) > 0:
            # Filter projects based on security risk selection
            secvals = []
            if 'Critical' in secrisk:
                temp_df_proj = temp_df_proj[temp_df_proj.secCritCount > 0]
                temp_df_comp = temp_df_comp[temp_df_comp.secCritCount > 0]
                secvals.append('CRITICAL')
            if 'High' in secrisk:
                temp_df_proj = temp_df_proj[temp_df_proj.secHighCount > 0]
                temp_df_comp = temp_df_comp[temp_df_comp.secHighCount > 0]
                secvals.append('HIGH')
            if 'Medium' in secrisk:
                temp_df_proj = temp_df_proj[temp_df_proj.secMedCount > 0]
                temp_df_comp = temp_df_comp[temp_df_comp.secMedCount > 0]
                secvals.append('MEDIUM')
            if 'Low' in secrisk:
                temp_df_proj = temp_df_proj[temp_df_proj.secLowCount > 0]
                temp_df_comp = temp_df_comp[temp_df_comp.secLowCount > 0]
                secvals.append('LOW')
            if isinstance(secrisk, list):
                temp_df_vuln = temp_df_vuln[temp_df_vuln.severity.isin(secvals)]
            else:
                temp_df_vuln = temp_df_vuln[temp_df_vuln.severity in secvals]

        if licrisk is not None and len(licrisk) > 0 and len(temp_df_proj) > 0:
            # Filter projects based on security risk selection
            if 'High' in licrisk:
                temp_df_lic = temp_df_lic[temp_df_lic.licHighCount > 0]
                temp_df_proj = temp_df_proj[temp_df_proj.licHighCount > 0]
                temp_df_comp = temp_df_comp[temp_df_comp.licHighCount > 0]

            if 'Medium' in licrisk:
                temp_df_lic = temp_df_lic[temp_df_lic.licMedCount > 0]
                temp_df_proj = temp_df_proj[temp_df_proj.licMedCount > 0]
                temp_df_comp = temp_df_comp[temp_df_comp.licMedCount > 0]

            if 'Low' in licrisk:
                temp_df_lic = temp_df_lic[temp_df_lic.licLowCount > 0]
                temp_df_proj = temp_df_proj[temp_df_proj.licLowCount > 0]
                temp_df_comp = temp_df_comp[temp_df_comp.licLowCount > 0]
    except:
        noprojs = True
        # sel_tiers_options = [{'label': i, 'value': i} for i in df_proj.projTier.unique()]
        # sel_dists_options = [{'label': i, 'value': i} for i in df_proj.projVerDist.unique()]
        # sel_phases_options = [{'label': i, 'value': i} for i in df_proj.projVerPhase.unique()]
        # sel_comps_options = [{'label': i, 'value': i} for i in df_comp.compName.sort_values().unique()]

    if len(temp_df_proj) == 0 or len(temp_df_comp) == 0 or len(temp_df_vuln) == 0 or len(temp_df_lic) == 0:
        noprojs = True

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

    return (
        create_alltabs(temp_df_proj, temp_df_comp, temp_df_vuln, temp_df_lic,
                       proj_treemap_color, proj_treemap_size, noprojs),
        proj_treemap_color, proj_treemap_size,
    )


if __name__ == '__main__':
    app.run_server(debug=True)
