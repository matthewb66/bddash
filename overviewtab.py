import dash_bootstrap_components as dbc
import dash_core_components as dcc
import plotly.express as px
import plotly.graph_objects as go
import dash_html_components as html


def create_fig_projmap(projdf, childdata):
    if projdf is None:
        return None

    fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=childdata['parentlabels'] + childdata['childlabels'],
                    # color="blue",
                ),
                link=dict(
                    source=childdata['sources'],  # indices correspond to labels, eg A1, A2, A1, B1, ...
                    target=childdata['targets'],
                    value=childdata['values']
                )
            )
        ],
    )

    fig.update_layout(height=800)

    return fig


def create_fig_projphasepol(projphasedf):
    if projphasedf is None:
        return None
    projphasedf['All'] = 'All'

    fig = px.sunburst(projphasedf, path=['All', 'projverphase', 'polseverity', "secrisk"],
                      values='projcount',
                      color='secAll',
                      # hover_data=['iso_alpha'],
                      color_continuous_scale='Reds',
                      labels={
                          "polseverity": "Policy Severity",
                          "projverphase": "Project Phase",
                          "secrisk": "Top Security Risk Level",
                          "secAll": "Count of all Vulnerabilities",
                          "projcount": "Number of Projects",

                      },
                      # color_continuous_midpoint=np.average(df['secAll'],weights=df['pop']))
                      title='Projects by Phase, Policy & Security Risk'
                      )
    return fig


# def create_fig_projdistsec(projdistdf):
#
#     temp_df = projdistdf.groupby(["projverphase"]).sum().reset_index()
#
#     sorter = ["PLANNING", "DEVELOPMENT", "PRERELEASE", "RELEASE", "DEPRECATED", "ARCHIVED"]
#     # temp_df.projverdist = temp_df.projverdist.astype("category")
#     # temp_df.projverdist.cat.set_categories(sorter, inplace=True)
#
#     vals = []
#     secvals = []
#     for dist in sorter:
#         thisdf = temp_df[temp_df.projverphase == dist]
#         if len(thisdf) > 0:
#             # vals += list(thisdf.secAll.values)
#             vals += list([0])
#             secvals += list(thisdf.seccritcount.values)
#             secvals += list(thisdf.sechighcount.values)
#             secvals += list(thisdf.secmedcount.values)
#             secvals += list(thisdf.seclowcount.values)
#         else:
#             vals += list([0])
#             secvals += list([0, 0, 0, 0])
#
#     data = dict(
#         labels=["All", "EXTERNAL", "SAAS", "INTERNAL", "OPEN SOURCE",
#                 "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE",
#                 "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE",
#                 "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE",
#                 "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE",
#                 ],
#         parent=["", "All", "All", "All", "All",
#                 "EXTERNAL", "EXTERNAL", "EXTERNAL", "EXTERNAL", "EXTERNAL",
#                 "SAAS", "SAAS", "SAAS", "SAAS", "SAAS",
#                 "INTERNAL", "INTERNAL", "INTERNAL", "INTERNAL", "INTERNAL",
#                 "OPEN SOURCE", "OPEN SOURCE", "OPEN SOURCE", "OPEN SOURCE", "OPEN SOURCE",
#                 ],
#         value=vals + secvals,
#     )
#
#     fig = px.sunburst(
#         data,
#         names='labels',
#         parents='parent',
#         values='value',
#         title='Projects by Phase & Security Risk',
#     )
#
#     return fig


def create_fig_compsec(comppolsecdf):
    if comppolsecdf is None:
        return None
    # comppolsecdf['All'] = 'All'

    # comppolsecdf.drop(['licriskNoUnk', 'compcount', 'secmedcount', 'seclowcount', 'secokcount'],
    #                   axis=1, inplace=True)

    print(comppolsecdf.to_string())
    fig = px.bar(
        comppolsecdf,
        x="polseverity",
        y=["seccritcount", "sechighcount", "secmedcount", "seclowcount", "secokcount"],
        labels={
         "polseverity": "Policy Severity",
         'y': 'Component Count'
        },
        category_orders={  # replaces default order by column name
         "polseverity": ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "TRIVIAL", "UNSPECIFIED", "NONE"]
        },
        color_discrete_map={  # replaces default color mapping by value
         "seccritcount": 'maroon',
         "sechighcount": 'crimson',
         "secmedcount": 'coral',
         "seclowcount": 'gold',
         "secokcount": 'green',
        },
        title="Components by Policy & Security Risk"
    )
    fig.data[0].name = "Critical Security Risk"
    fig.data[1].name = "High Security Risk"
    fig.data[2].name = "Medium Security Risk"
    fig.data[3].name = "Low Security Risk"
    fig.data[4].name = "No Security Risk"

    # fig = px.sunburst(comppolsecdf, path=['All', 'polseverity', "secrisk"],
    #                   values='compcount',
    #                   color='secrisk',
    #                   # hover_data=['iso_alpha'],
    #                   color_continuous_scale='Reds',
    #                   # labels={
    #                   #     "polseverity": "Policy Severity",
    #                   #     "projverphase": "Project Phase",
    #                   #     "secrisk": "Top Security Risk Level",
    #                   #     "secAll": "Count of all Vulnerabilities",
    #                   #     "projcount": "Number of Projects",
    #                   # },
    #                   # color_continuous_midpoint=np.average(df['secAll'],weights=df['pop']))
    #                   title='Components by Policy & Security Risk'
    #                   )
    return fig


# def create_fig_complic(projdistdf):
#     if projdistdf is None:
#         return None
#     projdistdf['All'] = 'All'
#
#     fig = px.bar(projdistdf, x="polseverity",
#                  y=["lichighcount", "licmedcount", "liclowcount", "licokcount"],
#                  labels={
#                      "polseverity": "Policy Severity",
#                  },
#                  category_orders={  # replaces default order by column name
#                      "polseverity": ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "TRIVIAL", "UNSPECIFIED"]
#                  },
#                  color_discrete_map={  # replaces default color mapping by value
#                      "lichighcount": 'crimson',
#                      "licmedcount": 'coral',
#                      "liclowcount": 'gold',
#                      "licokcount": 'green',
#                  },
#                  title="Components by Policy & License Risk")
#     fig.data[0].name = "High License Risk"
#     fig.data[1].name = "Medium License Risk"
#     fig.data[2].name = "Low License Risk"
#     fig.data[3].name = "No License Risk"
#     return fig


def create_overviewtab(projdf, projphasepoldf, comppolsecdf, childdata):
    return dbc.Row(
        dbc.Col(
            [
                dbc.Row(
                    [
                        dbc.Col(
                            dcc.Graph(figure=create_fig_projphasepol(projphasepoldf)), width=6
                        ),
                        dbc.Col(
                            dcc.Graph(figure=create_fig_compsec(comppolsecdf), ), width=6
                        ),
                        # dbc.Col(
                        #     [
                        #         html.Br(),
                        #         html.H4('Projects within Projects'),
                        #         dcc.Graph(figure=create_fig_projmap(projdf, childdata)),
                        #     ], width={"size": 6, "offset": 0}
                        # ),
                    ]
                ),
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                html.Br(),
                                html.H4('Projects within Projects'),
                                dcc.Graph(figure=create_fig_projmap(projdf, childdata)),
                            ], width={"size": 10, "offset": 1}
                        ),
                        # dbc.Col(
                        #     dcc.Graph(figure=create_fig_compsec(projdistpoldf), ), width=6
                        # ),
                        # dbc.Col(
                        #     dcc.Graph(figure=create_fig_complic(projdistpoldf), ), width=6
                        # ),
                    ]
                ),
            ]
        )
    )
