import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import dash_table
import pandas as pd
import plotly.express as px


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


def create_comptab_card_comp(compdata):
    import app

    compname = ''
    compver = ''
    complic = ''
    projusedbytitle = html.P('Used in Projects:', className="card-text", )
    projselbutton = html.Div(
        dbc.Button("Filter on Used In Project", color="primary", className="mr-1", id="filter_compcard_proj_button", size='sm'),
    )
    projusedin_cols = [
        {"name": ['Project'], "id": "projName"},
        {"name": ['Project Version'], "id": "projVerName"},
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
        compname = compdata['compName'].values[0]
        compver = compdata['compVerName'].values[0]
        compverid = compdata['compVerId'].values[0]
        complic = compdata['licName'].values[0]

        projlist = []
        projverlist = []

        for projid in app.df_projcompmap[app.df_projcompmap['compVerId'] == compverid].projVerId.unique():
            projlist.append(app.df_proj[app.df_proj['projVerId'] == projid].projName.values[0])
            projverlist.append(app.df_proj[app.df_proj['projVerId'] == projid].projVerName.values[0])

        projs_data = pd.DataFrame({
            "projName": projlist,
            "projVerName": projverlist
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
                            create_comptab_card_comp(None),
                            label='Selected Component',
                            tab_id="tab_comp_subdetail", id="tab_comp_subdetail",
                        ),
                    ], id='comptab_detail_tabs', active_tab='tab_comp_subsummary',
                ), width=4
            ),
        ]
    )


