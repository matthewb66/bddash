import dash_bootstrap_components as dbc
import dash_core_components as dcc
import plotly.express as px


def create_fig_projdistpol(projdistdf):
    if projdistdf is None:
        return None
    projdistdf['All'] = 'All'

    fig = px.sunburst(projdistdf, path=['All', 'projverdist', 'polseverity'], values='projcount',
                      title='Projects by Distribution & Policy Risk')
    fig.data[0].name = "Critical Security Risk"
    return fig


def create_fig_projdistphase(projdistdf):
    if projdistdf is None:
        return None
    projdistdf['All'] = 'All'

    fig = px.sunburst(projdistdf, path=['All', 'projverdist', 'projverphase'], values='projcount',
                       title='Projects by Distribution & Phase')
    return fig


def create_fig_projdistsec(projdistdf):
    # fig = go.Figure(go.Sunburst(
    #     labels=["All",
    #             "External", "SaaS", "Internal", "Open Source",
    #             "Critical", "High", "Medium", "Low", "None",
    #             "Critical", "High", "Medium", "Low", "None",
    #             "Critical", "High", "Medium", "Low", "None",
    #             "Critical", "High", "Medium", "Low", "None",
    #             ],
    #     parents=["",
    #              "All", "All", "All", "All",
    #              "External", "External", "External", "External", "External",
    #              "SaaS", "SaaS", "SaaS", "SaaS", "SaaS",
    #              "Internal", "Internal", "Internal", "Internal", "Internal",
    #              "Open Source", "Open Source", "Open Source", "Open Source", "Open Source",
    #              ],
    #     values=[10, 14, 12, 10, 2,
    #             6, 6, 4, 4, 3,
    #             1, 3, 5, 3, 1,
    #             2, 6, 7, 1, 3,
    #             2, 0, 6, 7, 8, ],
    # ))
    # fig.update_layout(margin=dict(t=0, l=0, r=0, b=0))

    temp_df = projdistdf.groupby(["projverdist"]).sum().reset_index()

    sorter = ["EXTERNAL", "SAAS", "INTERNAL", "OPENSOURCE", "NONE"]
    # temp_df.projverdist = temp_df.projverdist.astype("category")
    # temp_df.projverdist.cat.set_categories(sorter, inplace=True)

    vals = []
    secvals = []
    for dist in sorter:
        thisdf = temp_df[temp_df.projverdist == dist]
        if thisdf.size > 0:
            # vals += list(thisdf.secAll.values)
            vals += list([0])
            secvals += list(thisdf.seccritcount.values)
            secvals += list(thisdf.sechighcount.values)
            secvals += list(thisdf.secmedcount.values)
            secvals += list(thisdf.seclowcount.values)
        else:
            vals += list([0])
            secvals += list([0, 0, 0, 0])

    data = dict(
        labels=["All", "External", "SaaS", "Internal", "Open Source",
                "Critical", "High", "Medium", "Low", "None",
                "Critical", "High", "Medium", "Low", "None",
                "Critical", "High", "Medium", "Low", "None",
                "Critical", "High", "Medium", "Low", "None",
                ],
        parent=["", "All", "All", "All", "All",
                 "External", "External", "External", "External", "External",
                 "SaaS", "SaaS", "SaaS", "SaaS", "SaaS",
                 "Internal", "Internal", "Internal", "Internal", "Internal",
                 "Open Source", "Open Source", "Open Source", "Open Source", "Open Source",
                 ],
        value=vals + secvals,
    )

    # data = dict(
    #     character=["Eve", "Cain", "Seth", "Enos", "Noam", "Abel", "Awan", "Enoch", "Azura"],
    #     parent=["", "Eve", "Eve", "Seth", "Seth", "Eve", "Eve", "Awan", "Eve"],
    #     value=[10, 14, 12, 10, 2, 6, 6, 4, 4])

    fig = px.sunburst(
        data,
        names='labels',
        parents='parent',
        values='value',
        title='Projects by Distribution & Security Risk',
    )

    return fig


def create_fig_compsec(projdistdf):
    if projdistdf is None:
        return None
    projdistdf['All'] = 'All'

    fig = px.bar(projdistdf, x="polseverity",
                 y=["seccritcount", "sechighcount", "secmedcount", "seclowcount", "secokcount"],
                 labels={
                     "polseverity": "Policy Severity",
                     'y': 'Component Count'
                 },
                 category_orders={  # replaces default order by column name
                     "polseverity": ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "TRIVIAL", "UNSPECIFIED"]
                 },
                 color_discrete_map={  # replaces default color mapping by value
                     "seccritcount": 'maroon',
                     "sechighcount": 'crimson',
                     "secmedcount": 'coral',
                     "seclowcount": 'gold',
                     "secokcount": 'green',
                 },
                 title="Components by Policy & Security Risk")
    fig.data[0].name = "Critical Security Risk"
    fig.data[1].name = "High Security Risk"
    fig.data[2].name = "Medium Security Risk"
    fig.data[3].name = "Low Security Risk"
    fig.data[4].name = "No Security Risk"
    return fig


def create_fig_complic(projdistdf):
    if projdistdf is None:
        return None
    projdistdf['All'] = 'All'

    fig = px.bar(projdistdf, x="polseverity",
                 y=["lichighcount", "licmedcount", "liclowcount", "licokcount"],
                 labels={
                     "polseverity": "Policy Severity",
                 },
                 category_orders={  # replaces default order by column name
                     "polseverity": ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "TRIVIAL", "UNSPECIFIED"]
                 },
                 color_discrete_map={  # replaces default color mapping by value
                     "lichighcount": 'crimson',
                     "licmedcount": 'coral',
                     "liclowcount": 'gold',
                     "licokcount": 'green',
                 },
                 title="Components by Policy & License Risk")
    fig.data[0].name = "High License Risk"
    fig.data[1].name = "Medium License Risk"
    fig.data[2].name = "Low License Risk"
    fig.data[3].name = "No License Risk"
    return fig


def create_overviewtab(projdistpoldf, projdistphasedf):
    return dbc.Row(
        dbc.Col(
            [
                dbc.Row(
                    [
                        dbc.Col(
                            dcc.Graph(figure=create_fig_projdistphase(projdistphasedf), ), width=4
                        ),
                        dbc.Col(
                            dcc.Graph(figure=create_fig_projdistpol(projdistpoldf), ), width=4
                        ),
                        dbc.Col(
                            dcc.Graph(figure=create_fig_projdistsec(projdistpoldf), ), width=4
                        ),
                    ]
                ),
                dbc.Row(
                    [
                        dbc.Col(
                            dcc.Graph(figure=create_fig_compsec(projdistpoldf), ), width=6
                        ),
                        dbc.Col(
                            dcc.Graph(figure=create_fig_complic(projdistpoldf), ), width=6
                        ),
                    ]
                ),
            ]
        )
    )
