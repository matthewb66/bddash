import dash_bootstrap_components as dbc
import dash_html_components as html
import dash_table
import pandas as pd


def create_vulntab_table_vulns(thisdf):
    # "projName", "projVerName", "compName", "compVerName", "vulnId", "relatedVulnId",
    # "vulnSource", "severity", "remStatus"))
    vuln_data = [
        {"name": ['Vuln Id'], "id": "vulnId"},
        {"name": ['Related Vuln'], "id": "relatedVulnId"},
        {"name": ['Severity'], "id": "severity"},
        {"name": ['CVSS3 Score'], "id": "score"},
        {"name": ['Rem Status'], "id": "remStatus"},
        # {"name": ['Description'], "id": "desc"},
        {"name": ['Solution'], "id": "solution"},
        {"name": ['Workaround'], "id": "workaround"},
        # {"name": ['Comment'], "id": "comment"},
        {"name": ['Published Date'], "id": "published_on"},
    ]
    df_temp = thisdf

    if len(df_temp) == 0:
        thistable = dash_table.DataTable(id='vulntab_table_vulns',
                                         columns=vuln_data,
                                         )
    else:
        df_temp = df_temp.sort_values(by=["score"], ascending=False)

        thistable = dash_table.DataTable(id='vulntab_table_vulns',
                                         columns=vuln_data,
                                         data=df_temp.to_dict('records'),
                                         page_size=20,
                                         sort_action='native',
                                         filter_action='native',
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


def create_vulntab_card_vuln(vulndata):
    import app

    vulnid = ''
    vulnrelated = ''
    desc = ''
    projusedin_cols = [
        {"name": ['Project'], "id": "projName"},
        {"name": ['Project Version'], "id": "projVerName"},
    ]
    compusedin_cols = [
        {"name": ['Component'], "id": "compName"},
        {"name": ['Component Version'], "id": "compVerName"},
    ]
    usedbyprojstitle = html.P('Exposed in Projects:', className="card-text", )
    usedbycompstitle = html.P('Exposed in Components:', className="card-text", )
    projstable = dash_table.DataTable(
        columns=projusedin_cols,
        # data=projs_data.to_dict('records'),
        # page_size=4, sort_action='native',
        # row_selectable="single",
        # merge_duplicate_headers=False,
        id='vulntab_card_projtable'
    )
    compstable = dash_table.DataTable(
        columns=compusedin_cols,
        # data=comps_data.to_dict('records'),
        # page_size=4, sort_action='native',
        # row_selectable="single",
        # sort_by=[{'column_id': 'score', 'direction': 'desc'}],
        # merge_duplicate_headers=False,
        id='vulntab_card_comptable'
    )
    projselbutton = html.Div(
        dbc.Button("Filter on Project", color="primary", className="mr-1", id="filter_vulncard_proj_button", size='sm'),
    )
    compselbutton = html.Div(
        dbc.Button("Filter on Component", color="primary", className="mr-1", id="filter_vulncard_comp_button",
                   size='sm'),
    )
    if vulndata is not None:
        vulnid = vulndata['vulnId'].values[0]
        vulnrelated = vulndata['relatedVulnId'].values[0]
        if vulnrelated == '':
            vulnrelated = 'None'
        desc = vulndata['desc'].values[0]

        projlist = []
        projverlist = []
        for projid in app.df_projvulnmap[app.df_projvulnmap['vulnId'] == vulnid].projVerId.unique():
            projlist.append(app.df_proj[app.df_proj['projVerId'] == projid].projName.values[0])
            projverlist.append(app.df_proj[app.df_proj['projVerId'] == projid].projVerName.values[0])

        complist = []
        compverlist = []
        for compid in app.df_compvulnmap[app.df_compvulnmap['vulnId'] == vulnid].compVerId.unique():
            complist.append(app.df_comp[app.df_comp['compVerId'] == compid].compName.values[0])
            compverlist.append(app.df_comp[app.df_comp['compVerId'] == compid].compVerName.values[0])

        projs_data = pd.DataFrame({
            "projName": projlist,
            "projVerName": projverlist
        })

        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            page_size=4, sort_action='native',
            row_selectable="single",
            merge_duplicate_headers=False,
            id='vulntab_card_projtable'
        )

        comps_data = pd.DataFrame({
            "compName": complist,
            "compVerName": compverlist
        })

        compstable = dash_table.DataTable(
            columns=compusedin_cols,
            data=comps_data.to_dict('records'),
            page_size=4, sort_action='native',
            row_selectable="single",
            merge_duplicate_headers=False,
            id='vulntab_card_comptable'
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
            usedbyprojstitle, projstable, projselbutton,
            usedbycompstitle, compstable, compselbutton,
        ], id="vulntab_card_vuln",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "28rem"},
    )


def create_vulntab(vulndf):
    return dbc.Row(
        [
            dbc.Col(
                [
                    dbc.Row(
                        dbc.Col(
                            create_vulntab_table_vulns(vulndf),
                            width=12,
                        )
                    ),
                    dbc.Row(
                        dbc.Col(
                            dbc.Button("Select Vulnerability", id="sel_vuln_button", className="mr-2", size='sm'),
                            width={"size": 3, "offset": 9}, align='center',
                        ),
                    ),
                ], width=8
            ),
            dbc.Col(create_vulntab_card_vuln(None), width=4, id='col_vulntab_vuln'),
        ]
    )


