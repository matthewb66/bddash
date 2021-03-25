import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import plotly.express as px
import pandas as pd


def create_projsummtab_fig_proj(thisdf, color_column, size_column):
    if size_column == 'seccritcountplus1':
        sizetext = 'Critical Vulnerabilities'
    elif size_column == 'seccrithighcountplus1':
        sizetext = 'Critical & High Vulnerabilities'
    elif size_column == 'lichighcountplus1':
        sizetext = 'High License Risk'
    else:
        sizetext = 'Components'

    if color_column == 'seccritcountplus1':
        colortext = 'Critical Vulnerabilities'
    elif color_column == 'seccrithighcountplus1':
        colortext = 'Critical & High Vulnerabilities'
    elif color_column == 'lichighcountplus1':
        colortext = 'High License Risk'
    else:
        colortext = 'Components'

    hovertext = "<br>".join([
        "Project: %{parent}",
        "Version: %{label}",
        sizetext + ": %{value}",
        colortext + ": %{customdata[0]}"
    ])

    temp_df = thisdf.nlargest(200, size_column)
    thisfig = px.treemap(temp_df, path=['All', 'projname', 'projvername'],
                         custom_data=[color_column],
                         values=size_column,
                         color=color_column,
                         # hover_data={'projname':True, 'projvername':True, 'secAll':':2d', 'seccritcount':True,
                         #             'sechighcount':True, 'lichighcount':True, 'compcount':True},
                         # hover_data={'projname': True, 'projvername': True,},
                         # hover_name='projname',
                         color_continuous_scale='Reds',
                         labels={
                             "projname": "Project Name",
                             "projvername": "Project Version Name",
                             "secrisk": "Top Security Risk Level",
                             "secAll": "Count of all Vulnerabilities",
                             "projcount": "Number of Projects",

                         },
                         title='Top 200 Project Versions - Size by ' + sizetext,
                         height=700)
    thisfig.data[0].textinfo = 'label+text+value'
    # thisfig.update_traces(hovertemplate="<br"'Project: %{parent} <br>Project Version: %{label}')  #

    thisfig.update_traces(
            hovertemplate=hovertext
    )

    return thisfig


def create_projsummtab_fig_compsec(thisdf):
    # print(thisdf.head(20).to_string())
    sec_labels = ['Critical', 'High', 'Medium', 'Low', 'OK']
    sec_names = ['Critical', 'High', 'Medium', 'Low', 'OK']

    # sec_values = [len(thisdf[thisdf['seccritcount'] > 0]), len(thisdf[thisdf['sechighcount'] > 0]),
    #                len(thisdf[thisdf['secmedcount'] > 0]), len(thisdf[thisdf['seclowcount'] > 0]),
    #                len(thisdf[thisdf['secokcount'] > 0])]
    sec_values = [thisdf.seccritcount.sum(), thisdf.sechighcount.sum(), thisdf.secmedcount.sum(),
                  thisdf.seclowcount.sum(), thisdf.secokcount.sum()]

    thisfig = px.pie(values=sec_values, labels=sec_labels, names=sec_names,
                     title='Component Security Risk',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(sort=False)
    return thisfig


def create_projsummtab_fig_complic(thisdf):
    lic_labels = ['High', 'Medium', 'Low', 'OK']
    lic_names = ['High', 'Medium', 'Low', 'None']
    # lic_values = [len(thisdf[thisdf['lichighcount'] > 0]), len(thisdf[thisdf['licmedcount'] > 0]),
    #               len(thisdf[thisdf['liclowcount'] > 0]), len(thisdf[thisdf['licokcount'] > 0])]
    lic_values = [thisdf.lichighcount.sum(), thisdf.licmedcount.sum(), thisdf.liclowcount.sum(),
                  thisdf.licokcount.sum()]

    thisfig = px.pie(values=lic_values, labels=lic_labels, names=lic_names, title='Component License Risk',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(sort=False)
    return thisfig


def create_projsummtab(projdf, color_col, size_col):
    return dbc.Row([
        dbc.Col([
            dbc.Row(
                dbc.Col(
                    dcc.Graph(id='projsummtab_graph_proj',
                              figure=create_projsummtab_fig_proj(projdf, color_col, size_col,),
                    ),
                ),
            ),
            dbc.Row([
                dbc.Col(
                    html.Div(children="Box Sizing", style={'font-size': '18px'},), width=2,
                ),
                dbc.Col(
                    dbc.RadioItems(
                        options=[
                            {'label': 'Component Count', 'value': 'compcount'},
                            {'label': 'Critical Vulns', 'value': 'seccritcountplus1'},
                            {'label': 'Crit & High Vulns', 'value': 'seccrithighcountplus1'},
                            {'label': 'High Licenses', 'value': 'lichighcountplus1'},
                        ],
                        id='summtab_size_radio',
                        value=size_col,
                        inline=True,
                        # labelStyle={'display': 'inline-block'}
                    ), width=8,
                )], justify='end'
            ),
            dbc.Row([
                dbc.Col(
                    html.Div(children="Colour Scheme", style={'font-size': '18px'},), width=2,
                ),
                dbc.Col(
                    dbc.RadioItems(
                        options=[
                            {'label': 'Component Count', 'value': 'compcount'},
                            {'label': 'Critical Vulns', 'value': 'seccritcountplus1'},
                            {'label': 'Crit & High Vulns', 'value': 'seccrithighcountplus1'},
                            {'label': 'High Licenses', 'value': 'lichighcountplus1'},
                        ],
                        id='summtab_color_radio',
                        value=color_col,
                        inline=True,
                        # labelStyle={'display': 'inline-block'}
                    ), width=8,
                )], justify='end'
            ),
        ], width=8),
        dbc.Col([
            dcc.Graph(id='projsummtab_graph_compsec', figure=create_projsummtab_fig_compsec(projdf)),
            dcc.Graph(id='projsummtab_graph_complic', figure=create_projsummtab_fig_complic(projdf)),
        ], width=4),
    ])
