import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import dash_table
import pandas as pd
import plotly.express as px


def create_comptab_fig_compsec(thisdf):
    df_temp = thisdf[["seccritcount", "sechighcount", "secmedcount", "seclowcount", "secokcount"]].sum()
    sec_labels = ['Critical', 'High', 'Medium', 'Low']
    sec_names = ['Critical', 'High', 'Medium', 'Low']
    compsec_values = [df_temp.seccritcount.sum(), df_temp.sechighcount.sum(), df_temp.secmedcount.sum(),
                      df_temp.seclowcount.sum()]
    thisfig = px.pie(values=compsec_values, labels=sec_labels, names=sec_names,
                     title='Vulnerability Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_comptab_fig_complic(thisdf):
    lic_labels = ['High', 'Medium', 'Low', 'OK']
    lic_names = ['High', 'Medium', 'Low', 'None']
    complic_values = [thisdf.lichighcount.sum(), thisdf.licmedcount.sum(), thisdf.liclowcount.sum(),
                      thisdf.licokcount.sum()]
    thisfig = px.pie(values=complic_values, labels=lic_labels, names=lic_names, title='License Risk Counts',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(textinfo='value')
    thisfig.update_traces(sort=False)
    return thisfig


def create_comptab_table_compvers(thisdf):
    col_data = [
        {"name": ['', 'Component'], "id": "compname"},
        {"name": ['', 'Version'], "id": "compvername"},
        {"name": ['Vulnerabilities', 'Crit'], "id": "seccritcount"},
        {"name": ['Vulnerabilities', 'High'], "id": "sechighcount"},
        {"name": ['Vulnerabilities', 'Medium'], "id": "secmedcount"},
        {"name": ['Vulnerabilities', 'Low'], "id": "seclowcount"},
        {"name": ['License', 'Risk'], "id": "licrisk"},
        {"name": ['License', 'Name'], "id": "licname"},
    ]
    df_temp = thisdf

    if len(df_temp) == 0:
        thistable = dash_table.DataTable(id='comptab_table_compvers',
                                         columns=col_data,
                                         style_cell={
                                             'overflow': 'hidden',
                                             'textOverflow': 'ellipsis',
                                             'maxWidth': 0
                                         },
                                         data=df_temp.to_dict('records'),
                                         row_selectable="single",
                                         page_size=20,
                                         sort_action='native',
                                         filter_action='native',
                                         cell_selectable=False,
                                         style_data_conditional=[
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
                                                 'width': '50px'
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
                                                 'width': '50px'
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
                                                 'width': '50px'
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
                                                 'width': '50px'
                                             },
                                             {
                                                 'if': {'column_id': 'licname'},
                                                 'width': '300px',
                                                 'overflow': 'hidden',
                                                 'textOverflow': 'ellipsis',
                                             },
                                             {
                                                 'if': {'column_id': 'compname'},
                                                 'width': '400px',
                                             },
                                             {
                                                 'if': {'column_id': 'compvername'},
                                                 'width': '100px',
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{licrisk} = "High"',
                                                     'column_id': 'licrisk'
                                                 },
                                                 'backgroundColor': 'crimson',
                                                 'color': 'black',
                                                 'width': '50px',
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{licrisk} = "Medium"',
                                                     'column_id': 'licrisk'
                                                 },
                                                 'backgroundColor': 'coral',
                                                 'color': 'black',
                                                 'width': '50px',
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{licrisk} = "Low"',
                                                     'column_id': 'licrisk'
                                                 },
                                                 'backgroundColor': 'gold',
                                                 'color': 'black',
                                                 'width': '50px',
                                             },

                                         ],
                                         sort_by=[{'column_id': 'seccritcount', 'direction': 'desc'},
                                                  {'column_id': 'sechighcount', 'direction': 'desc'},
                                                  {'column_id': 'secmedcount', 'direction': 'desc'},
                                                  {'column_id': 'seclowcount', 'direction': 'desc'}],
                                         merge_duplicate_headers=True
                                         )
    else:
        thistable = dash_table.DataTable(id='comptab_table_compvers',
                                         columns=col_data,
                                         style_cell={
                                             'overflow': 'hidden',
                                             'textOverflow': 'ellipsis',
                                             'maxWidth': 0
                                         },
                                         data=df_temp.to_dict('records'),
                                         row_selectable="single",
                                         page_size=20,
                                         sort_action='native',
                                         filter_action='native',
                                         cell_selectable=False,
                                         style_data_conditional=[
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
                                                 'width': '50px'
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
                                                 'width': '50px'
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
                                                 'width': '50px'
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
                                                 'width': '50px'
                                             },
                                             {
                                                 'if': {'column_id': 'licname'},
                                                 'width': '300px',
                                                 'overflow': 'hidden',
                                                 'textOverflow': 'ellipsis',
                                             },
                                             {
                                                 'if': {'column_id': 'compname'},
                                                 'width': '400px',
                                             },
                                             {
                                                 'if': {'column_id': 'compvername'},
                                                 'width': '100px',
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{licrisk} = "High"',
                                                     'column_id': 'licrisk'
                                                 },
                                                 'backgroundColor': 'crimson',
                                                 'color': 'black',
                                                 'width': '50px',
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{licrisk} = "Medium"',
                                                     'column_id': 'licrisk'
                                                 },
                                                 'backgroundColor': 'coral',
                                                 'color': 'black',
                                                 'width': '50px',
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{licrisk} = "Low"',
                                                     'column_id': 'licrisk'
                                                 },
                                                 'backgroundColor': 'gold',
                                                 'color': 'black',
                                                 'width': '50px',
                                             },

                                         ],
                                         sort_by=[{'column_id': 'seccritcount', 'direction': 'desc'},
                                                  {'column_id': 'sechighcount', 'direction': 'desc'},
                                                  {'column_id': 'secmedcount', 'direction': 'desc'},
                                                  {'column_id': 'seclowcount', 'direction': 'desc'}],
                                         merge_duplicate_headers=True
                                         )
    return thistable


def create_comptab_card_comp(projdf, projcompmapdf, compdata):
    # from app import df_proj, df_projcompmap

    compname = ''
    compver = ''
    complic = ''
    projusedbytitle = html.P('Used in Projects:', className="card-text", )
    projselbutton = html.Div(
        dbc.Button("Filter on Used In Project", color="primary", className="mr-1",
                   id="filter_compcard_proj_button", size='sm'),
    )
    projusedin_cols = [
        {"name": ['Project'], "id": "projname"},
        {"name": ['Project Version'], "id": "projvername"},
    ]
    projstable = dash_table.DataTable(
        columns=projusedin_cols,
        # data=projs_data.to_dict('records'),
        # page_size=6, sort_action='native',
        row_selectable="single",
        # merge_duplicate_headers=False,
        id='comptab_card_projtable'
    )

    if compdata is not None:
        compname = compdata['compname'].values[0]
        compver = compdata['compvername'].values[0]
        compverid = compdata['compverid'].values[0]
        complic = compdata['licname'].values[0]

        projlist = []
        projverlist = []

        for projid in projcompmapdf[projcompmapdf['compverid'] == compverid].projverid.unique():
            projlist.append(projdf[projdf['projverid'] == projid].projname.values[0])
            projverlist.append(projdf[projdf['projverid'] == projid].projvername.values[0])

        projs_data = pd.DataFrame({
            "projname": projlist,
            "projvername": projverlist
        })

        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            page_size=6, sort_action='native',
            row_selectable="single",
            merge_duplicate_headers=False,
            id='comptab_card_projtable',
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
                    html.Br(),
                    html.P("License: " + complic)
                ],
            ),
            dbc.Table(table_header + table_body, bordered=True),
            projusedbytitle, projstable,
            projselbutton,
        ], id="comptab_card_comp",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "23rem"},
    )


def create_comptab(compdf):
    return dbc.Row(
        [
            dbc.Col(
                [
                    dbc.Row(
                        dbc.Col(
                            create_comptab_table_compvers(compdf),
                            width=12,
                        ),
                    ),
                    dbc.Row(
                        dbc.Col(
                            dbc.Button("Select Component", id="sel_comp_button", className="mr-2", size='sm'),
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
                                dcc.Graph(id='comptab_graph_compsec', figure=create_comptab_fig_compsec(compdf)),
                                dcc.Graph(id='comptab_graph_complic', figure=create_comptab_fig_complic(compdf)),
                            ], label='Components Summary',
                            tab_id="tab_comp_subsummary", id="tab_comp_subsummary",
                        ),
                        dbc.Tab(
                            create_comptab_card_comp(None, None, None),
                            label='Selected Component',
                            tab_id="tab_comp_subdetail", id="tab_comp_subdetail",
                        ),
                    ], id='comptab_detail_tabs', active_tab='tab_comp_subsummary',
                ), width=4
            ),
        ]
    )
