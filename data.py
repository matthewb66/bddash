import pandas as pd
import re


# def proc_projdata(projdf):
#     newdf = projdf
#     newdf["All"] = "All"
#
#     newdf = pd.DataFrame(newdf.eval('secAll = seccritcount + sechighcount + secmedcount + seclowcount'))
#     newdf = pd.DataFrame(newdf.eval('seccrithighcountplus1 = seccritcount + sechighcount + 1'))
#     newdf = pd.DataFrame(newdf.eval('seccritcountplus1 = seccritcount + 1'))
#     newdf = pd.DataFrame(newdf.eval('lichighcountplus1 = lichighcount + 1'))
#
#     # Sum columns for projVers
#     sums = newdf.groupby("projverid").sum().reset_index()
#     # Remove duplicate component rows
#     newdf.drop_duplicates(subset="projverid", keep="first", inplace=True)
#     # Count components in projvers
#     df_counts = pd.DataFrame(projdf['projverid'].value_counts(ascending=False).
#                              rename_axis('projverid').reset_index(name='compcount'))
#
#     # Merge compcount into df
#     newdf = pd.merge(newdf, df_counts, on='projverid')
#     # Remove duplicate and unwanted columns before merge
#     newdf.drop(['secAll', 'seccrithighcountplus1', 'seccritcountplus1', 'lichighcountplus1',
#                 'seccritcount', 'sechighcount', 'secmedcount',
#                 'seclowcount', 'secokcount', 'lichighcount', 'licmedcount', 'liclowcount', 'licokcount', 'compid',
#                 'compname', 'compverid', 'compvername', 'licname'], axis=1, inplace=True)
#     # Merge sums into df
#     newdf = pd.merge(newdf, sums, on='projverid')
#     print('{} Projects and {} Versions returned'.format(newdf.projname.nunique(), newdf.projverid.nunique()))
#
#     return newdf


def proc_comp_data(thisdf, serverurl):
    # compdf will have 1 row per compver across all projvers
    # -  license risk will be the most severe across all projvers
    # projcompdf will have 1 row for each compver within each projver
    # - will map projverid to compverid

    thisdf.astype(
        {
            'projname': str,
            'projvername': str,
            'projid': str,
            'projverid': str,
            'projverdist': str,
            'projverphase': str,
            'projtier': str,
            'compid': str,
            'compname': str,
            'compverid': str,
            'compvername': str,
            'seccritcount': int,
            'secmedcount': int,
            'seclowcount': int,
            'secokcount': int,
            'lichighcount': int,
            'licmedcount': int,
            'liclowcount': int,
            'licokcount': int,
            'licname': str,
        }
    )

    # Calculate mapping of projvers to compvers
    projcompmapdf = thisdf[['projverid', 'compverid']]

    projdf = thisdf
    projdf["All"] = "All"

    projdf = pd.DataFrame(projdf.eval('secAll = seccritcount + sechighcount + secmedcount + seclowcount'))
    projdf = pd.DataFrame(projdf.eval('seccrithighcountplus1 = seccritcount + sechighcount + 1'))
    projdf = pd.DataFrame(projdf.eval('seccritcountplus1 = seccritcount + 1'))
    projdf = pd.DataFrame(projdf.eval('lichighcountplus1 = lichighcount + 1'))
    # projdf['projverurl'] = serverurl + '/api/projects/' + projdf['projid'].astype(str) + '/versions/' \
    #     + projdf['projverid'] + '/components'

    # Sum columns for projVers
    sums = projdf.groupby("projverid").sum().reset_index()
    # Count components in projvers
    df_counts = pd.DataFrame(projdf['projverid'].value_counts(ascending=False).
                             rename_axis('projverid').reset_index(name='compcount'))
    # Merge compcount into df
    projdf = pd.merge(projdf, df_counts, on='projverid')
    # Remove duplicate component rows
    projdf.drop_duplicates(subset="projverid", keep="first", inplace=True)
    # Remove duplicate and unwanted columns before merge
    projdf.drop(['secAll', 'seccrithighcountplus1', 'seccritcountplus1', 'lichighcountplus1',
                 'seccritcount', 'sechighcount', 'secmedcount',
                 'seclowcount', 'secokcount', 'lichighcount', 'licmedcount', 'liclowcount', 'licokcount', 'compid',
                 'compname', 'compverid', 'compvername', 'licname'], axis=1, inplace=True)
    # Merge sums into df
    projdf = pd.merge(projdf, sums, on='projverid')
    print('{} Projects and {} Versions returned'.format(projdf.projname.nunique(), projdf.projverid.nunique()))

    projdf = projdf.set_index('projverid', drop=True)
    projdf = projdf.sort_index()

    # compdf = tempdf
    # remove duplicates
    compdf = thisdf
    compdf = compdf.drop_duplicates(subset="compverid", keep="first", inplace=False)

    # sort by license risk
    # compdf = compdf.sort_values(by=['lichighcount', 'licmedcount', 'liclowcount'], ascending=False)

    # Calculate license risk value as licrisk
    def calc_license(row):
        if row['lichighcount'] > 0:
            return 'High'
        elif row['licmedcount'] > 0:
            return 'Medium'
        elif row['liclowcount'] > 0:
            return 'Low'
        elif row['licokcount'] > 0:
            return 'OK'
        return ''

    testdf = compdf.apply(calc_license, axis=1, result_type='expand')
    compdf.insert(5, 'licrisk', testdf)
    compdf = compdf.drop(["projname", "projvername", "projverid", "projverdist", "projverphase", "projtier"],
                         axis=1, inplace=False)

    # compdf = compdf.sort_values(by=['compname'], ascending=True)

    def calc_lic_nounknown(row):
        if row['licname'] == 'Unknown License':
            return 1
        else:
            return 0

    # compdf[['licriskNoUnk']] = compdf.apply(calc_lic_nounknown, axis=1)
    testdf = compdf.apply(calc_lic_nounknown, axis=1, result_type='expand')
    compdf.insert(5, 'licriskNoUnk', testdf)

    compdf = compdf.set_index('compverid', drop=True)
    compdf = compdf.sort_index()

    # Create maps of projs to comps and comps to projs
    projcompmapdf = projcompmapdf.set_index('projverid', drop=True)
    projcompmapdf = projcompmapdf.sort_index()

    # projcompmapdf = projcompmapdf.sort_values(['projverid', 'compverid'], ascending=False)

    print('{} Components and {} Component Versions returned'.format(compdf.compname.nunique(),
                                                                    len(compdf)))

    # Process projects in projects
    projchildmap = {}
    childprojlist = []
    comps_as_projs = 0
    comps_as_projs_parents = 0
    parentlabels = []
    childlabels = []
    tuples = []
    projdf['parent'] = False
    projdf['child'] = False
    for testid in projdf.index.values:
        projsusingcompdf = projcompmapdf[projcompmapdf.compverid == testid]
        if len(projsusingcompdf) > 0:
            # testid is a project and component
            projdf.loc[testid, 'child'] = True

            # Find projs where it is used
            comps_as_projs += 1
            usedinprojids = projsusingcompdf.index.values
            for projverid in usedinprojids:
                projdf.loc[testid, 'parent'] = True

                df = projdf.loc[projverid]
                parent = '/'.join((df['projname'], df['projvername']))
                df = projdf.loc[testid]
                child = '/'.join((df['projname'], df['projvername']))

                # add components from child project (testid) to parent project (projverid)
                # newcomps = df.replace({testid: projverid}, inplace=False)
                newcomps = projcompmapdf.loc[testid].replace({testid: projverid}, inplace=False)
                # projcompmapdf.append(newcomps)

                # Remove the component (child project) testid from projverid in projcompmap
                uncomp = projcompmapdf[~((projcompmapdf.compverid == testid) &
                                         (projcompmapdf.index == projverid))]
                projcompmapdf = pd.concat([uncomp, newcomps])

                comps_as_projs_parents += 1
                childprojlist.append(testid)
                if child not in childlabels:
                    childlabels.append(child)
                if projverid in projchildmap.keys():
                    projchildmap[projverid].append(testid)
                else:
                    projchildmap[projverid] = [testid]
                    parentlabels.append(parent)
                print('Parent = ' + parent + ' - Child = ' + child)
                tuples.append((parentlabels.index(parent), childlabels.index(child)))

    sources = []
    targets = []
    values = []

    for tup in tuples:
        sources.append(tup[0])
        targets.append(len(parentlabels) + tup[1])
        sp = childlabels[tup[1]].split('/')
        val = projdf[(projdf.projname == sp[0]) & (projdf.projvername == sp[1])].compcount.values[0]
        values.append(val)

    projdf['parent'] = False
    projdf['child'] = False
    for proj in projchildmap.keys():
        projdf.loc[proj, 'parent'] = True
    for child in childprojlist:
        projdf.loc[child, 'child'] = True

    print("Found {} projects within {} projects".format(comps_as_projs, comps_as_projs_parents))

    childdata = {
        'parentlabels': parentlabels,
        'childlabels': childlabels,
        'sources': sources,
        'targets': targets,
        'values': values,
    }

    return projdf, compdf, projcompmapdf, childdata


def proc_licdata(thisdf):
    licnames = thisdf.licname.values
    compids = thisdf.index.values
    # licrisks = thisdf.licrisk.values

    thislic_compverid_dict = {}  # Map of license names to compverids (dict of lists of compverids)
    thiscompverid_lic_dict = {}  # Map of compverids to licnames (dict of lists of licnames)
    # licrisk_dict = {}
    licname_list = []

    tempdf = thisdf
    sums = tempdf[~tempdf['licname'].str.startswith('(') &
                  ~tempdf['licname'].str.endswith(')')].groupby("licname").sum().reset_index()
    # print(sums.head(100).to_string())

    compindex = 0

    # def get_maxlicrisk(riskarray):
    #     for risk in ['High', 'Medium', 'Low', 'OK']:
    #         if risk in riskarray:
    #             return risk

    for lic in licnames:
        if lic not in licname_list:
            licname_list.append(lic)
        splits = [lic]

        if lic[0] == '(' and lic[-1] == ')':
            lic = lic[1:-1]
            if ' AND ' in lic or ' OR ' in lic:
                splits = re.split(' OR | AND ', lic)

        for item in splits:
            # lics = thisdf[thisdf['licname'] == item].licrisk.unique()
            # maxrisk = get_maxlicrisk(lics)
            compverid = compids[compindex]
            if item not in thislic_compverid_dict.keys():
                thislic_compverid_dict[item] = [compverid]
            elif compverid not in thislic_compverid_dict[item]:
                thislic_compverid_dict[item].append(compverid)

            if compverid not in thiscompverid_lic_dict.keys():
                thiscompverid_lic_dict[compverid] = [item]
            elif item not in thiscompverid_lic_dict[compverid]:
                thiscompverid_lic_dict[compverid].append(item)

                # licrisk_dict[item] = maxrisk
            # print(item, ' - ', maxrisk, ' - ', lic)

        compindex += 1

    # print(list(zip(licmap_dict.keys(), licrisk_dict.values())))
    print("{} Licenses returned".format(len(sums)))
    # temp_df = pd.DataFrame.from_records(list(zip(licmap_dict.keys(),
    #                                     licrisk_dict.values())), columns=['licname', 'licrisk'])
    # sorter = ['OK', 'Low', 'Medium', 'High']
    # temp_df.licrisk = temp_df.licrisk.astype("category")
    # temp_df.licrisk.cat.set_categories(sorter, inplace=True)
    return sums, thislic_compverid_dict, thiscompverid_lic_dict


def proc_vuln_data(thisdf):
    # vulndf will have 1 row per vulnid
    # projvulnmapdf will have 1 row for each vuln within each projver
    # - will map projverid to compverid

    thisdf = thisdf.astype(
        {
            'projverid': str,
            'compid': str,
            'compverid': str,
            'compname': str,
            'compvername': str,
            'projvername': str,
            'projname': str,
            'vulnid': str,
            'relatedvulnid': str,
            'vulnsource': str,
            'severity': str,
            'score': float,
            'remstatus': str,
            'solution': bool,
            'workaround': bool,
            'pubdate': str,
            'description': str,
            'targetdate': str,
            'actualdate': str,
            'comment': str,
            'attackvector': str,
            'updateddate': str,
        }
    )

    vuln_active_list = thisdf[thisdf['remstatus'].isin(['NEW', 'NEEDS_REVIEW', 'REMEDIATION_REQUIRED'])].vulnid.unique()
    # vuln_inactive_list = vulndf[~vulndf['remstatus'].isin(['NEW', 'NEEDS_REVIEW',
    #                                                          'REMEDIATION_REQUIRED'])].vulnid.unique()

    vulndf = thisdf.drop_duplicates(subset=["vulnid"], keep="first", inplace=False)
    # vulndf = vulndf.sort_values(by=['score'], ascending=False)
    vulndf = vulndf.drop(["projname", "projvername", "compname", "compid", "compverid",
                          "compvername", "remstatus"],
                         axis=1, inplace=False)

    vulndf = vulndf.set_index('vulnid', drop=False)
    vulndf = vulndf.sort_index()

    vulnmapdf = thisdf[["vulnid", "projverid", "compverid"]]
    vulnmapdf = vulnmapdf.set_index('vulnid', drop=False)
    vulnmapdf = vulnmapdf.sort_index()

    print('{} Vulnerabilities returned'.format(len(vulndf)))
    return vulndf, vulnmapdf, vuln_active_list


def proc_pol_data(projdf, compdf, poldf):
    def tm_sorter(column):
        """Sort function"""
        severities = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'TRIVIAL', 'UNSPECIFIED']
        correspondence = {polseverity: order for order, polseverity in enumerate(severities)}
        return column.map(correspondence)

    poldf = poldf.astype(
        {
            'projverid': str,
            'compverid': str,
            'polid': str,
            'polname': str,
            'polstatus': str,
            'overrideby': str,
            'desc': str,
            'polseverity': str,
        }
    )

    poldf.sort_values(by='polseverity', key=tm_sorter, inplace=True, ascending=True)
    polmapdf = poldf[['polid', 'projverid', 'compverid']]
    # Add policies to projects
    # SELECT
    # component_policies.project_version_id as projverid,
    # component.component_version_id as compverid,
    # policy_id as polid,
    # policy_name as polname,
    # policy_status as polstatus,
    # overridden_by as overrideby,
    # description as desc,
    # polseverity

    tempdf = poldf.drop_duplicates(subset=["projverid"], keep="first", inplace=False)
    projdf = pd.merge(projdf, tempdf, on='projverid', how='outer')
    projdf.fillna(value='', inplace=True)
    projdf = projdf.set_index('projverid', drop=False)
    projdf = projdf.sort_index()

    tempdf = poldf.drop_duplicates(subset=["compverid"], keep="first", inplace=False)
    compdf = pd.merge(compdf, tempdf, on='compverid', how='outer')
    compdf.fillna(value='', inplace=True)
    compdf = compdf.drop_duplicates(subset=["compverid"], keep="first", inplace=False)
    compdf = compdf.set_index('compverid', drop=False)
    compdf = compdf.sort_index()

    poldf = poldf.drop_duplicates(subset=["polid"], keep="first", inplace=False)
    print('{} Policies returned'.format(poldf.polid.nunique()))

    poldf = poldf.set_index('polid', drop=False)
    poldf = poldf.sort_index()

    return projdf, compdf, poldf, polmapdf


def proc_overviewdata(projdf, compdf):
    # Need counts of projects by:
    # - Phase
    # - Policy severity risk
    # - Security risk
    # Need counts of components by:
    # - Policy severity risk
    # - Security risk

    tempdf = projdf[['polseverity']].mask(projdf['polseverity'] == '', 'NONE', inplace=False)
    projdf['polseverity'] = tempdf['polseverity']

    def calc_security(row):
        if row['seccritcount'] > 0:
            return 'CRITICAL'
        elif row['sechighcount'] > 0:
            return 'HIGH'
        elif row['secmedcount'] > 0:
            return 'MEDIUM'
        elif row['seclowcount'] > 0:
            return 'LOW'
        elif row['secokcount'] > 0:
            return 'OK'
        return 'NONE'

    proj_phasepolsecdf = projdf[['projverid', 'projvername', 'projid', 'projverdist',
           'projverphase', 'All', 'compcount', 'secAll', 'polseverity', 'seccritcount',
           'sechighcount', 'secmedcount', 'seclowcount', 'secokcount']]
    testdf = proj_phasepolsecdf.apply(calc_security, axis=1, result_type='expand')
    proj_phasepolsecdf.insert(5, 'secrisk', testdf)
    tempdf = proj_phasepolsecdf.groupby(["projverphase", "polseverity", "secrisk"]).count().reset_index()
    proj_phasepolsecdf = proj_phasepolsecdf.groupby(["projverphase", "polseverity", "secrisk"]).max().reset_index()
    # proj_phasepolsecdf = pd.merge(proj_phasepolsecdf, tempdf['projname'])
    proj_phasepolsecdf.insert(5, 'projcount', tempdf['projvername'])

    # temp_df = projdf.groupby(["projverphase", "polseverity", "secrisk"]).count().reset_index()
    # proj_phasepolsecdf['projcount'] = temp_df['projname']

    comp_polsecdf = compdf
    tempdf = comp_polsecdf[['polseverity']].mask(comp_polsecdf['polseverity'] == '', 'NONE', inplace=False)
    comp_polsecdf['polseverity'] = tempdf['polseverity']

    testdf = comp_polsecdf.apply(calc_security, axis=1, result_type='expand')
    comp_polsecdf.insert(5, 'secrisk', testdf)
    tempdf = comp_polsecdf.groupby(["polseverity", "secrisk"]).count().reset_index()
    comp_polsecdf = comp_polsecdf.groupby(["polseverity", "secrisk"]).sum().reset_index()
    comp_polsecdf.insert(5, 'compcount', tempdf['compverid'])

    return proj_phasepolsecdf, comp_polsecdf
