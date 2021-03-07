import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import plotly.express as px


def create_projsummtab_fig_proj(thisdf, color_column, size_column):
    if size_column == 'secCritCountplus1':
        sizetext = 'Critical Vulnerabilities'
    elif size_column == 'secCritHighCountplus1':
        sizetext = 'Critical & High Vulnerabilities'
    elif size_column == 'licHighCountplus1':
        sizetext = 'High License Risk'
    else:
        sizetext = 'Components'

    if color_column == 'secCritCountplus1':
        colortext = 'Critical Vulnerabilities'
    elif color_column == 'secCritHighCountplus1':
        colortext = 'Critical & High Vulnerabilities'
    elif color_column == 'licHighCountplus1':
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
    thisfig = px.treemap(temp_df, path=['All', 'projName', 'projVerName'],
                         custom_data=[color_column],
                         values=size_column,
                         color=color_column,
                         # hover_data={'projName':True, 'projVerName':True, 'secAll':':2d', 'secCritCount':True,
                         #             'secHighCount':True, 'licHighCount':True, 'compCount':True},
                         # hover_data={'projName': True, 'projVerName': True,},
                         # hover_name='projName',
                         color_continuous_scale='Reds',
                         title='Top 200 Project Versions - Size by ' + sizetext,
                         height=700)
    thisfig.data[0].textinfo = 'label+text+value'
    # thisfig.update_traces(hovertemplate="<br"'Project: %{parent} <br>Project Version: %{label}')  #

    thisfig.update_traces(
            hovertemplate=hovertext
    )

    return thisfig


def create_projsummtab_fig_compsec(thisdf):
    sec_labels = ['Critical', 'High', 'Medium', 'Low', 'OK']
    sec_names = ['Critical', 'High', 'Medium', 'Low', 'OK']

    # sec_values = [len(thisdf[thisdf['secCritCount'] > 0]), len(thisdf[thisdf['secHighCount'] > 0]),
    #                len(thisdf[thisdf['secMedCount'] > 0]), len(thisdf[thisdf['secLowCount'] > 0]),
    #                len(thisdf[thisdf['secOkCount'] > 0])]
    sec_values = [thisdf.secCritCount.sum(), thisdf.secHighCount.sum(), thisdf.secMedCount.sum(),
                  thisdf.secLowCount.sum(), thisdf.secOkCount.sum()]

    thisfig = px.pie(values=sec_values, labels=sec_labels, names=sec_names,
                     title='Component Security Risk',
                     hole=0.3, color_discrete_sequence=px.colors.sequential.RdBu, height=400)
    thisfig.update_traces(sort=False)
    return thisfig


def create_projsummtab_fig_complic(thisdf):
    lic_labels = ['High', 'Medium', 'Low', 'OK']
    lic_names = ['High', 'Medium', 'Low', 'None']
    # lic_values = [len(thisdf[thisdf['licHighCount'] > 0]), len(thisdf[thisdf['licMedCount'] > 0]),
    #               len(thisdf[thisdf['licLowCount'] > 0]), len(thisdf[thisdf['licOkCount'] > 0])]
    lic_values = [thisdf.licHighCount.sum(), thisdf.licMedCount.sum(), thisdf.licLowCount.sum(),
                  thisdf.licOkCount.sum()]

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
                              figure=create_projsummtab_fig_proj(projdf, color_col, size_col,)
                    ),
                ),
            ),
            dbc.Row([
                dbc.Col(
                    html.Div(children="Box Sizing"), width=3,
                ),
                dbc.Col(
                    dbc.RadioItems(
                        options=[
                            {'label': 'Component Count', 'value': 'compCount'},
                            {'label': 'Critical Vulns', 'value': 'secCritCountplus1'},
                            {'label': 'Crit & High Vulns', 'value': 'secCritHighCountplus1'},
                            {'label': 'High Licenses', 'value': 'licHighCountplus1'},
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
                    html.Div(children="Colour Scheme"), width=3,
                ),
                dbc.Col(
                    dbc.RadioItems(
                        options=[
                            {'label': 'Component Count', 'value': 'compCount'},
                            {'label': 'Critical Vulns', 'value': 'secCritCountplus1'},
                            {'label': 'Crit & High Vulns', 'value': 'secCritHighCountplus1'},
                            {'label': 'High Licenses', 'value': 'licHighCountplus1'},
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