import dash_bootstrap_components as dbc
import dash_html_components as html
import dash_table
import pandas as pd


def create_poltab_table_pols(thisdf):
    # SELECT
    # component_policies.project_version_id as projverid,
    # component.component_version_id as compverid,
    # policy_id as polid,
    # policy_name as polname,
    # policy_status as polstatus,
    # overridden_by as overrideby,
    # description as desc,
    # severity

    pol_cols = [
        {"name": ['Policy'], "id": "polname"},
        {"name": ['Dewscription'], "id": "desc"},
        {"name": ['Severity'], "id": "polseverity"},
    ]
    df_temp = thisdf

    if df_temp is None or len(df_temp) == 0:
        thistable = dash_table.DataTable(id='poltab_table_pols',
                                         columns=pol_cols,
                                         )
    else:
        # df_temp = df_temp.sort_values(by=["severity"], ascending=False)
        def tm_sorter(column):
            """Sort function"""
            severities = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'TRIVIAL', 'UNSPECIFIED']
            correspondence = {polseverity: order for order, polseverity in enumerate(severities)}
            return column.map(correspondence)

        df_temp.sort_values(by='polseverity', key=tm_sorter, inplace=True)

        thistable = dash_table.DataTable(id='poltab_table_pols',
                                         columns=pol_cols,
                                         data=df_temp.to_dict('records'),
                                         style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                                         page_size=20,
                                         sort_action='native',
                                         filter_action='native',
                                         row_selectable="single",
                                         cell_selectable=False,
                                         style_data_conditional=[
                                             {
                                                 'if': {
                                                     'filter_query': '{polseverity} = "BLOCKER"',
                                                     'column_id': 'polseverity'
                                                 },
                                                 'backgroundColor': 'maroon',
                                                 'color': 'white'
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{polseverity} = "CRITICAL"',
                                                     'column_id': 'polseverity'
                                                 },
                                                 'backgroundColor': 'crimson',
                                                 'color': 'black'
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{polseverity} = "MAJOR"',
                                                     'column_id': 'polseverity'
                                                 },
                                                 'backgroundColor': 'coral',
                                                 'color': 'black'
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{polseverity} = "MINOR"',
                                                     'column_id': 'polseverity'
                                                 },
                                                 'backgroundColor': 'gold',
                                                 'color': 'black'
                                             },
                                             {
                                                 'if': {'column_id': 'polseverity'},
                                                 'width': '120px'
                                             },
                                         ],
                                         sort_by=[{'column_id': 'polseverity', 'direction': 'asc'}],
                                         merge_duplicate_headers=False
                                         )
    return thistable


def create_poltab_card_pol(projdf, compdf, projpolmapdf, comppolmapdf, poldata):
    polname = ''
    desc = ''
    projusedin_cols = [
        {"name": ['Project'], "id": "projname"},
        {"name": ['Project Version'], "id": "projvername"},
    ]
    compusedin_cols = [
        {"name": ['Component'], "id": "compname"},
        {"name": ['Component Version'], "id": "compvername"},
    ]
    usedbyprojstitle = html.P('Projects with Violations:', className="card-text", )
    usedbycompstitle = html.P('Components with Violations:', className="card-text", )
    projstable = dash_table.DataTable(
        columns=projusedin_cols,
        style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
        id='poltab_card_projtable'
    )
    compstable = dash_table.DataTable(
        columns=compusedin_cols,
        style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
        # data=comps_data.to_dict('records'),
        # page_size=4, sort_action='native',
        # row_selectable="single",
        # sort_by=[{'column_id': 'score', 'direction': 'desc'}],
        # merge_duplicate_headers=False,
        id='poltab_card_comptable'
    )
    projselbutton = html.Div(
        dbc.Button("Filter on Project", color="primary", className="mr-1", id="filter_polcard_proj_button", size='sm'),
    )
    compselbutton = html.Div(
        dbc.Button("Filter on Component", color="primary", className="mr-1", id="filter_polcard_comp_button",
                   size='sm'),
    )
    if poldata is not None:
        polid = poldata['polid'].values[0]
        polname = poldata['polname'].values[0]
        desc = poldata['desc'].values[0]

        # projlist = []
        # projverlist = []
        # for projid in projpolmapdf[projpolmapdf['polid'] == polid].projverid.unique():
        #     projlist.append(projdf[projdf['projverid'] == projid].projname.values[0])
        #     projverlist.append(projdf[projdf['projverid'] == projid].projvername.values[0])
        #
        # complist = []
        # compverlist = []
        # for compid in comppolmapdf[comppolmapdf['polid'] == polid].compverid.unique():
        #     complist.append(compdf[compdf['compverid'] == compid].compname.values[0])
        #     compverlist.append(compdf[compdf['compverid'] == compid].compvername.values[0])
        #
        projlist = []
        projverlist = []
        for projid in projdf.projverid:
            if projpolmapdf[(projpolmapdf['polid'] == polid)].size > 0:
                projlist.append(projdf[projdf.projverid == projid].projname.values[0])
                projverlist.append(projdf[projdf.projverid == projid].projvername.values[0])

        complist = []
        compverlist = []
        for compid in compdf.compverid:
            if comppolmapdf[(comppolmapdf['polid'] == polid)].size > 0:
                complist.append(compdf[compdf.compverid == compid].compname.values[0])
                compverlist.append(compdf[compdf.compverid == compid].compvername.values[0])

        projs_data = pd.DataFrame({
            "projname": projlist,
            "projvername": projverlist
        })

        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
            page_size=4, sort_action='native',
            row_selectable="single",
            filter_action='native',
            merge_duplicate_headers=False,
            id='poltab_card_projtable'
        )

        comps_data = pd.DataFrame({
            "compname": complist,
            "compvername": compverlist
        })

        compstable = dash_table.DataTable(
            columns=compusedin_cols,
            data=comps_data.to_dict('records'),
            style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
            page_size=4, sort_action='native',
            row_selectable="single",
            filter_action='native',
            merge_duplicate_headers=False,
            id='poltab_card_comptable'
        )

    return dbc.Card(
        [
            dbc.CardHeader("Policy Details"),
            dbc.CardBody(
                [
                    html.H4("Policy: " + polname, className="card-title"),
                    # html.H6("Description: " , className="card-subtitle"),

                    html.P(desc),
                ],
            ),
            usedbyprojstitle, projstable, projselbutton,
            usedbycompstitle, compstable, compselbutton,
        ], id="poltab_card_pol",
        # style={"width": "28rem", "height":  "50rem"},
        # style={"width": "28rem"},
    )


def create_poltab(poldf):
    if poldf is not None:
        poldf = poldf.drop_duplicates(subset=["polid"], keep="first", inplace=False)
        poldf = poldf.sort_values(by=['polname'], ascending=True)

    return dbc.Row(
        [
            dbc.Col(
                [
                    dbc.Row(
                        dbc.Col(
                            create_poltab_table_pols(poldf),
                            width=12,
                        )
                    ),
                    dbc.Row(
                        dbc.Col(
                            dbc.Button("Select Policy", id="sel_pol_button", className="mr-2", size='sm'),
                            width={"size": 3, "offset": 9}, align='center',
                        ),
                    ),
                ], width=8
            ),
            dbc.Col(create_poltab_card_pol(None, None, None, None, None), width=4, id='col_poltab_pol'),
        ]
    )
