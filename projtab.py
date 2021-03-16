import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import dash_table
import pandas as pd
import plotly.express as px


def create_projtab_table_projs(thisdf):
    # projname projvername projverid projverdist projverphase projtier  All  compcount
    # seccritcount  sechighcount  secmedcount  seclowcount  secokcount
    # lichighcount  licmedcount  liclowcount  licokcount  secAll
    col_data = [
        {"name": ['', 'Project'], "id": "projname"},
        {"name": ['', 'Project Version'], "id": "projvername"},
        {"name": ['', 'Comps'], "id": "compcount"},
        {"name": ['Vulnerabilities', 'Crit'], "id": "seccritcount"},
        {"name": ['Vulnerabilities', 'High'], "id": "sechighcount"},
        {"name": ['Vulnerabilities', 'Med'], "id": "secmedcount"},
        {"name": ['Vulnerabilities', 'Low'], "id": "seclowcount"},
        {"name": ['License Risk', 'High'], "id": "lichighcount"},
        {"name": ['License Risk', 'Med'], "id": "licmedcount"},
        {"name": ['License Risk', 'Low'], "id": "liclowcount"},
        {"name": ['License Risk', 'None'], "id": "licokcount"},
        {"name": ['Policy', 'Violations'], "id": "polseverity"},
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
                                     page_size=20, sort_action='native',
                                     filter_action='native',
                                     row_selectable="single",
                                     cell_selectable=False,
                                     style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                                     tooltip_data=[
                                         {
                                             column: {'value': str(value), 'type': 'markdown'}
                                             for column, value in row.items()
                                         } for row in df_temp.to_dict('records')
                                     ],
                                     tooltip_duration=None,
                                     style_data_conditional=[
                                         {
                                             'if': {'column_id': 'projname'},
                                             'width': '25%'
                                         },
                                         {
                                             'if': {'column_id': 'projvername'},
                                             'width': '15%'
                                         },
                                         {
                                             'if': {'column_id': 'compcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{seccritcount} > 0',
                                                 'column_id': 'seccritcount'
                                             },
                                             'backgroundColor': 'maroon',
                                             'color': 'white'
                                         },
                                         {
                                             'if': {'column_id': 'seccritcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{sechighcount} > 0',
                                                 'column_id': 'sechighcount'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'sechighcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{secmedcount} > 0',
                                                 'column_id': 'secmedcount'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'secmedcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{seclowcount} > 0',
                                                 'column_id': 'seclowcount'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'seclowcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{lichighcount} > 0',
                                                 'column_id': 'lichighcount'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black',
                                         },
                                         {
                                             'if': {'column_id': 'lichighcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licmedcount} > 0',
                                                 'column_id': 'licmedcount'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black',
                                         },
                                         {
                                             'if': {'column_id': 'licmedcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{liclowcount} > 0',
                                                 'column_id': 'liclowcount'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black',
                                         },
                                         {
                                             'if': {'column_id': 'liclowcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licokcount} > 0',
                                                 'column_id': 'licokcount'
                                             },
                                             'width': '5%',
                                         },
                                         {
                                             'if': {'column_id': 'licokcount'},
                                             'width': '5%'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{polseverity} = "BLOCKER"',
                                                 'column_id': 'polseverity'
                                             },
                                             'backgroundColor': 'indigo',
                                             'color': 'white',
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{polseverity} = "CRITICAL"',
                                                 'column_id': 'polseverity'
                                             },
                                             'backgroundColor': 'darkviolet',
                                             'color': 'white',
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{polseverity} = "MAJOR"',
                                                 'column_id': 'polseverity'
                                             },
                                             'backgroundColor': 'violet',
                                             'color': 'black',
                                         },
                                         {
                                             'if': {'column_id': 'polseverity'},
                                             'width': '10%'
                                         },
                                     ],
                                     sort_by=[{'column_id': 'seccritcount', 'direction': 'desc'},
                                              {'column_id': 'sechighcount', 'direction': 'desc'},
                                              {'column_id': 'secmedcount', 'direction': 'desc'},
                                              {'column_id': 'seclowcount', 'direction': 'desc'}],
                                     merge_duplicate_headers=True
                                     )
    return thistable


def create_projtab_fig_subsummary(thisdf):
    df_temp = thisdf[["seccritcount", "sechighcount", "secmedcount", "seclowcount", "secokcount"]].sum()
    sec_labels = ['Crit', 'High', 'Med', 'Low']
    sec_names = ['Critical', 'High', 'Medium', 'Low']
    compsec_values = [df_temp.seccritcount.sum(), df_temp.sechighcount.sum(), df_temp.secmedcount.sum(),
                      df_temp.seclowcount.sum()]
    thisfig = px.pie(values=compsec_values, labels=sec_labels, names=sec_names,
                     title='Vulnerability Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_projtab_fig_subdetails(thisdf):
    lic_labels = ['High', 'Med', 'Low', 'OK']
    lic_names = ['High', 'Med', 'Low', 'None']
    complic_values = [thisdf.lichighcount.sum(), thisdf.licmedcount.sum(), thisdf.liclowcount.sum(),
                      thisdf.licokcount.sum()]
    thisfig = px.pie(values=complic_values, labels=lic_labels, names=lic_names, title='License Risk Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_projtab_card_proj(projdf, compdf, projcompmapdf, polmapdf, projdata):

    # projname projvername projverid projverdist projverphase projtier  All  compcount
    # seccritcount  sechighcount  secmedcount  seclowcount  secokcount
    # lichighcount  licmedcount  liclowcount  licokcount  secAll
    projname = ''
    projver = ''
    projlink = ''
    row1 = ''
    row2 = ''
    row3 = ''
    row4 = ''

    projusedbytitle = html.P('Used as sub-project in Projects:', className="card-text", )
    projusedin_cols = [
        {"name": ['Project'], "id": "projname"},
        {"name": ['Project Version'], "id": "projvername"},
    ]
    projstable = dash_table.DataTable(
        # columns=[],
        # data=None,
        # page_size=6, sort_action='native',
        row_selectable="single",
        # sort_by=[{'column_id': 'score', 'direction': 'desc'}],
        id='projtab_detail_projtable',
    )
    usedprojbutton = html.Div(
        dbc.Button("Filter on Used in Project", id="filter_usedproj_button", className="mr-2", size='sm'),
    )
    thisprojbutton = html.Div(
        dbc.Button("Filter on Selected Project", id="filter_thisproj_button", className="mr-2",
                   size='sm')
    )

    poltext = []
    if projdata is not None:
        projname = projdata['projname'].values[0]
        projver = projdata['projvername'].values[0]
        projlink = projdata['projverurl'].values[0]
        foundcomps = compdf.loc[(compdf['compname'] == projname) & (compdf['compvername'] == projver)]
        comppols = polmapdf[polmapdf.projverid == projdata['projverid'].values[0]].polname.unique()
        for pol in comppols:
            poltext.append(html.Li(pol + ' (' + polmapdf[polmapdf.polname == pol].polseverity.values[0] + ')'))

        if foundcomps.size > 0:
            projlist = []
            projverlist = []
            for projids in projcompmapdf[projcompmapdf['compverid'] == foundcomps.
                                         compverid.values[0]].projverid.unique():
                projs = projdf[projdf['projverid'] == projids]
                projlist.append(projs.projname.values[0])
                projverlist.append(projs.projvername.values[0])

            projs_data = pd.DataFrame({
                "projname": projlist,
                "projvername": projverlist
            })

            projstable = dash_table.DataTable(
                columns=projusedin_cols,
                data=projs_data.to_dict('records'),
                page_size=6, sort_action='native',
                row_selectable="single",
                filter_action='native',
                # sort_by=[{'column_id': 'score', 'direction': 'desc'}],
                merge_duplicate_headers=False,
                id='projtab_detail_projtable',
            )

        row1 = html.Tr([html.Td("Distribution"), html.Td(projdata['projverdist'])])
        row2 = html.Tr([html.Td("Tier"), html.Td(projdata['projtier'])])
        row3 = html.Tr([html.Td("Phase"), html.Td(projdata['projverphase'])])
        row4 = html.Tr([html.Td("Total Vulns"), html.Td(projdata['secAll'])])

    table_header = []

    table_body = [html.Tbody([row1, row2, row3, row4])]

    return dbc.Card(
        [
            dbc.CardHeader("Project Version Details"),
            dbc.CardBody(
                [
                    html.H4("Project: " + projname, className="card-title"),
                    html.H5("Project Version: " + projver, className="card-subtitle"),
                    html.A("Project Link", href=projlink, target="_blank"),
                    html.Br(),
                    thisprojbutton,
                    html.Br(),
                    html.H6("Policies Violated: "),
                    html.Ul(poltext),
                ],
            ),
            dbc.Table(table_header + table_body, bordered=True),
            projusedbytitle, projstable,
            usedprojbutton,
        ], id="projtab_card_proj",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "23rem"},
    )


def create_projtab(projdf):
    return dbc.Row([
        dbc.Col(
            [
                dbc.Row(
                    dbc.Col(create_projtab_table_projs(projdf), width=12)
                ),
                dbc.Row(
                    dbc.Col(
                        dbc.Button("Select Project", id="sel_proj_button", className="mr-2", size='sm'),
                        width={"size": 2, "offset": 10}, align='center',
                    ),
                ),
            ], width=8
        ),
        dbc.Col(
            dbc.Tabs(
                [
                    dbc.Tab(
                        [
                            dcc.Graph(id='projtab_graph_compsec',
                                      figure=create_projtab_fig_subsummary(projdf)),
                            dcc.Graph(id='projtab_graph_complic',
                                      figure=create_projtab_fig_subdetails(projdf)),
                        ], label='Projects Summary',
                        tab_id="tab_proj_subsummary", id="tab_proj_subsummary",
                    ),
                    dbc.Tab(
                        create_projtab_card_proj(None, None, None, None, None),
                        label='Selected Project',
                        tab_id="tab_proj_subdetail", id="tab_proj_subdetail",
                    )
                ], id="tabs_proj_subtabs", active_tab='tab_proj_subsummary',
            ), width=4
        ),
    ])
