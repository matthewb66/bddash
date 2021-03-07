import dash_bootstrap_components as dbc
import dash_html_components as html
import dash_table
import pandas as pd


def create_lictab_table_lics(licdict):
    lic_cols = [
        {"name": ['', 'License Name'], "id": "licName"},
        {"name": ['License Risk (All Projects)', 'High Risk'], "id": "licHighCount"},
        {"name": ['License Risk (All Projects)', 'Medium Risk'], "id": "licMedCount"},
        {"name": ['License Risk (All Projects)', 'Low Risk'], "id": "licLowCount"},
        {"name": ['License Risk (All Projects)', 'No Risk'], "id": "licOkCount"},
    ]

    # columns = [{"name": i, "id": i} for i in df.columns],
    # [{'column-1': 4.5, 'column-2': 'montreal', 'column-3': 'canada'},
    #  {'column-1': 8, 'column-2': 'boston', 'column-3': 'america'}]

    if len(licdict) == 0:
        thistable = dash_table.DataTable(id='lictab_table_lics',
                                         columns=lic_cols,
                                         filter_action='native',
                                         )
    else:
        thistable = dash_table.DataTable(id='lictab_table_lics',
                                         columns=lic_cols,
                                         data=licdict.to_dict('records'),
                                         page_size=20, sort_action='native',
                                         filter_action='native',
                                         row_selectable="single",
                                         cell_selectable=False,
                                         style_data_conditional=[
                                         {
                                             'if': {
                                                 'filter_query': '{licHighCount} > 0',
                                                 'column_id': 'licHighCount'
                                             },
                                             'backgroundColor': 'crimson',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licMedCount} > 0',
                                                 'column_id': 'licMedCount'
                                             },
                                             'backgroundColor': 'coral',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {
                                                 'filter_query': '{licLowCount} > 0',
                                                 'column_id': 'licLowCount'
                                             },
                                             'backgroundColor': 'gold',
                                             'color': 'black'
                                         },
                                         {
                                             'if': {'column_id': 'licHighCount'},
                                             'width': '120px'
                                         },
                                         {
                                             'if': {'column_id': 'licMedCount'},
                                             'width': '120px'
                                         },
                                         {
                                             'if': {'column_id': 'licLowCount'},
                                             'width': '120px'
                                         },
                                         {
                                             'if': {'column_id': 'licOkCount'},
                                             'width': '120px'
                                         },
                                         ],
                                         sort_by=[{'column_id': 'licHighCount', 'direction': 'desc'},
                                                  {'column_id': 'licMedCount', 'direction': 'desc'},
                                                  {'column_id': 'licLowCount', 'direction': 'desc'},
                                                  {'column_id': 'licOkCount', 'direction': 'asc'}],
                                         merge_duplicate_headers=True,
                                     )
    return thistable


def create_lictab_card_lic(licdata):
    import app

    licname = ''

    usedbyprojstitle = ''
    usedbycompstitle = ''
    projstable = ''
    compstable = ''
    if licdata is not None:
        licname = licdata['licName'].values[0]

        complist = []
        compverlist = []
        projlist = []
        projverlist = []
        for compid in app.lic_compverid_dict[licdata.licName.values[0]]:
            complist.append(app.df_comp[app.df_comp['compVerId'] == compid].compName.values[0])
            compverlist.append(app.df_comp[app.df_comp['compVerId'] == compid].compVerName.values[0])
            for projverid in app.df_projcompmap[app.df_projcompmap['compVerId'] == compid].projVerId.values:
                projlist.append(app.df_proj[app.df_proj['projVerId'] == projverid].projName.values[0])
                projverlist.append(app.df_proj[app.df_proj['projVerId'] == projverid].projVerName.values[0])

        usedbycompstitle = html.P('Exposed in Components:', className="card-text", )

        # for projid in df_projvulnmap[df_projvulnmap['vulnId'] == vulnid].projVerId.unique():
        #     projlist.append(df_proj[df_proj['projVerId'] == projid].projName.values[0])
        #     projverlist.append(df_proj[df_proj['projVerId'] == projid].projVerName.values[0])
        usedbyprojstitle = html.P('Exposed in Projects:', className="card-text", )

        projs_data = pd.DataFrame({
            "projName": projlist,
            "projVerName": projverlist
        })

        projusedin_cols = [
            {"name": ['Project'], "id": "projName"},
            {"name": ['Project Version'], "id": "projVerName"},
        ]
        projstable = dash_table.DataTable(
            columns=projusedin_cols,
            data=projs_data.to_dict('records'),
            page_size=5, sort_action='native',
            # row_selectable="single",
            merge_duplicate_headers=False
        )

        comps_data = pd.DataFrame({
            "compName": complist,
            "compVerName": compverlist
        })

        compusedin_cols = [
            {"name": ['Component'], "id": "compName"},
            {"name": ['Component Version'], "id": "compVerName"},
        ]
        compstable = dash_table.DataTable(
            columns=compusedin_cols,
            data=comps_data.to_dict('records'),
            page_size=5, sort_action='native',
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
            dbc.Col(create_lictab_table_lics(licdf), width=7),
            dbc.Col(create_lictab_card_lic(None), width=5,
                    id='col_lictab_lic'),
        ]
    )


