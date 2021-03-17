import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import dash_table
import pandas as pd
import plotly.express as px
# import plotly.graph_objects as go


def create_overviewfig(projdf, compdf):

    # fig = go.Figure(go.Sunburst(
    #     labels=["All", "External", "SaaS", "Internal", "Open Source",
    #             "Blocker", "Critical", "Major", "Minor", "Trivial",
    #             "Blocker", "Critical", "Major", "Minor", "Trivial",
    #             "Blocker", "Critical", "Major", "Minor", "Trivial",
    #             "Blocker", "Critical", "Major", "Minor", "Trivial",
    #             ],
    #     parents=["", "All", "All", "All", "All",
    #              "External", "External", "External", "External", "External",
    #              "SaaS", "SaaS", "SaaS", "SaaS", "SaaS",
    #              "Internal", "Internal", "Internal", "Internal", "Internal",
    #              "Open Source", "Open Source", "Open Source", "Open Source", "Open Source", ],
    #     values=[10, 14, 12, 10, 2,
    #             6, 6, 4, 4, 3,
    #             1, 3, 5, 3, 1,
    #             2, 6, 7, 1, 3,
    #             2, 0, 6, 7, 8, ],
    # ))
    # fig.update_layout(margin=dict(t=0, l=0, r=0, b=0))

    return px.sunburst(projdf, path=['All', 'projvername'], values='compcount')


def create_overviewtab(projdf, compdf):
    return dbc.Row([
        dbc.Col(
            dcc.Graph(figure=create_overviewfig(projdf, compdf)), width=8
        ),
    ])
