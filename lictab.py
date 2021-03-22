import dash_bootstrap_components as dbc
import dash_html_components as html
import dash_table
import pandas as pd


def create_lictab_table_lics(licdict):
    lic_cols = [
        {"name": ['', 'License Name'], "id": "licname"},
        {"name": ['License Risk (All Projects)', 'High Risk'], "id": "lichighcount"},
        {"name": ['License Risk (All Projects)', 'Medium Risk'], "id": "licmedcount"},
        {"name": ['License Risk (All Projects)', 'Low Risk'], "id": "liclowcount"},
        {"name": ['License Risk (All Projects)', 'No Risk'], "id": "licokcount"},
    ]

    # columns = [{"name": i, "id": i} for i in df.columns],
    # [{'column-1': 4.5, 'column-2': 'montreal', 'column-3': 'canada'},
    #  {'column-1': 8, 'column-2': 'boston', 'column-3': 'america'}]

    if len(licdict) == 0:
        thistable = dash_table.DataTable(id='lictab_table_lics',
                                         columns=lic_cols,
                                         style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                                         filter_action='native',
                                         )
    else:
        thistable = dash_table.DataTable(id='lictab_table_lics',
                                         columns=lic_cols,
                                         style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                                         data=licdict.to_dict('records'),
                                         page_size=20, sort_action='native',
                                         filter_action='native',
                                         row_selectable="single",
                                         cell_selectable=False,
                                         tooltip_data=[
                                             {
                                                 column: {'value': str(value), 'type': 'markdown'}
                                                 for column, value in row.items()
                                             } for row in licdict.to_dict('records')
                                         ],
                                         tooltip_duration=None,
                                         style_data_conditional=[
                                             {
                                                 'if': {
                                                     'filter_query': '{lichighcount} > 0',
                                                     'column_id': 'lichighcount'
                                                 },
                                                 'backgroundColor': 'crimson',
                                                 'color': 'black'
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{licmedcount} > 0',
                                                     'column_id': 'licmedcount'
                                                 },
                                                 'backgroundColor': 'coral',
                                                 'color': 'black'
                                             },
                                             {
                                                 'if': {
                                                     'filter_query': '{liclowcount} > 0',
                                                     'column_id': 'liclowcount'
                                                 },
                                                 'backgroundColor': 'gold',
                                                 'color': 'black'
                                             },
                                             {
                                                 'if': {'column_id': 'lichighcount'},
                                                 'width': '12%'
                                             },
                                             {
                                                 'if': {'column_id': 'licmedcount'},
                                                 'width': '12%'
                                             },
                                             {
                                                 'if': {'column_id': 'liclowcount'},
                                                 'width': '12%'
                                             },
                                             {
                                                 'if': {'column_id': 'licokcount'},
                                                 'width': '12%'
                                             },
                                         ],
                                         sort_by=[{'column_id': 'lichighcount', 'direction': 'desc'},
                                                  {'column_id': 'licmedcount', 'direction': 'desc'},
                                                  {'column_id': 'liclowcount', 'direction': 'desc'},
                                                  {'column_id': 'licokcount', 'direction': 'asc'}],
                                         merge_duplicate_headers=True,
                                         )
    return thistable


def create_lictab_card_lic(projdf, compdf, projcompmapdf, lic_compverid_dict, licdata):
    # from app import df_proj, df_comp, df_projcompmap, lic_compverid_dict

    licname = ''

    usedbyprojstitle = ''
    usedbycompstitle = ''
    projstable = ''
    compstable = ''
    if licdata is not None:
        licname = licdata['licname']

        complist = []
        compverlist = []
        projlist = []
        projverlist = []
        for compid in lic_compverid_dict[licname]:
            complist.append(compdf.loc[compid]['compname'])
            compverlist.append(compdf.loc[compid]['compvername'])
            for projverid in projcompmapdf.loc[compid].index.values:
                projlist.append(projdf.loc[projverid]['projname'])
                projverlist.append(projdf.loc[projverid]['projvername'])

        usedbycompstitle = html.P('Exposed in Components:', className="card-text", )

        # for projid in df_projvulnmap[df_projvulnmap['vulnid'] == vulnid].projverid.unique():
        #     projlist.append(df_proj[df_proj['projverid'] == projid].projname.values[0])
        #     projverlist.append(df_proj[df_proj['projverid'] == projid].projvername.values[0])
        usedbyprojstitle = html.P('Exposed in Projects:', className="card-text", )

        projs_data = pd.DataFrame({
            "projname": projlist,
            "projvername": projverlist
        })

        projusedin_cols = [
            {"name": ['Project'], "id": "projname"},
            {"name": ['Project Version'], "id": "projvername"},
        ]
        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
            page_size=5, sort_action='native',
            filter_action='native',
            # row_selectable="single",
            merge_duplicate_headers=False
        )

        comps_data = pd.DataFrame({
            "compname": complist,
            "compvername": compverlist
        })

        compusedin_cols = [
            {"name": ['Component'], "id": "compname"},
            {"name": ['Component Version'], "id": "compvername"},
        ]
        compstable = dash_table.DataTable(
            columns=compusedin_cols,
            data=comps_data.to_dict('records'),
            style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
            page_size=5, sort_action='native',
            filter_action='native',
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


def create_lictab(licdf):
    return dbc.Row(
        [
            dbc.Col(
                [
                    dbc.Row(
                            dbc.Col(create_lictab_table_lics(licdf)),
                    ),
                    dbc.Row(
                        dbc.Col(
                                dbc.Button("Select License", id="sel_lic_button", className="mr-2", size='sm'),
                                width={"size": 2, "offset": 10},
                                align='center',
                        ),
                    ),
                ], width=8,
            ),
            dbc.Col(create_lictab_card_lic(None, None, None, None, None), width=4, id='col_lictab_lic'),
        ]
    )
