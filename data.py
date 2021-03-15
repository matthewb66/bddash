import pandas as pd
import re


def proc_projdata(projdf):
    newdf = projdf
    newdf["All"] = "All"

    newdf = pd.DataFrame(newdf.eval('secAll = seccritcount + sechighcount + secmedcount + seclowcount'))
    newdf = pd.DataFrame(newdf.eval('seccrithighcountplus1 = seccritcount + sechighcount + 1'))
    newdf = pd.DataFrame(newdf.eval('seccritcountplus1 = seccritcount + 1'))
    newdf = pd.DataFrame(newdf.eval('lichighcountplus1 = lichighcount + 1'))

    # Sum columns for projVers
    sums = newdf.groupby("projverid").sum().reset_index()
    # Remove duplicate component rows
    newdf.drop_duplicates(subset="projverid", keep="first", inplace=True)
    # Count components in projvers
    df_counts = pd.DataFrame(projdf['projverid'].value_counts(ascending=False).
                             rename_axis('projverid').reset_index(name='compcount'))

    # Merge compcount into df
    newdf = pd.merge(newdf, df_counts, on='projverid')
    # Remove duplicate and unwanted columns before merge
    newdf.drop(['secAll', 'seccrithighcountplus1', 'seccritcountplus1', 'lichighcountplus1',
                'seccritcount', 'sechighcount', 'secmedcount',
                'seclowcount', 'secokcount', 'lichighcount', 'licmedcount', 'liclowcount', 'licokcount', 'compid',
                'compname', 'compverid', 'compvername', 'licname'], axis=1, inplace=True)
    # Merge sums into df
    newdf = pd.merge(newdf, sums, on='projverid')
    print('{} Projects and {} Versions returned'.format(newdf.projname.nunique(), newdf.projverid.nunique()))

    return newdf


def proc_comp_data(thisdf):
    # compdf will have 1 row per compver across all projvers
    # -  license risk will be the most severe across all projvers
    # projcompdf will have 1 row for each compver within each projver
    # - will map projverid to compverid

    tempdf = thisdf

    comps_as_projs = 0
    comps_as_projs_parents = 0
    for projverid in tempdf.projverid.unique():
        if tempdf[tempdf.compverid == projverid].size > 0:
            # compverid is also a project
            # Find projs where it is used
            projsusingcomp = tempdf[tempdf.compverid == projverid]
            comps_as_projs += 1
            usedinprojids = projsusingcomp.projverid.unique()
            for projid in usedinprojids:
                # Need to replace component with components from matching sub-project
                newcomps = tempdf[tempdf.projverid == projverid].replace({projverid: projid}, inplace=False)

                # Remove the sub-proj component from projid
                tempdf = pd.concat([tempdf[~((tempdf.projverid == projid) & (tempdf.compverid == projverid))],
                                    newcomps])
                comps_as_projs_parents += 1

    # OLD
    # for projname in tempdf.projname.unique():
    #     for projvername in tempdf[tempdf.projname == projname].projvername.unique():
    #         projverid = tempdf[(tempdf.projname == projname) &
    #                            (tempdf.projvername == projvername)].projverid.values[0]
    #         comps = tempdf[(tempdf.compname == projname) & (tempdf.compvername == projvername)]
    #         if comps.size > 0:
    #             # projverid = tempdf[(tempdf.compname == projname) &
    #             #                    (tempdf.compvername == projvername)].projverid.values[0]
    #             for compverid in comps.compverid.unique():
    #                 projs_as_comps_dict[projverid] = compverid
    #                 #
    #                 # Need to add components within sub-project to containing projects
    #                 parentprojverids = tempdf[tempdf.compverid == compverid].projverid.values
    #                 print("Project {}/{} is component: projid {} parentprojid {} compid {}".format(projname,
    #                                                 projvername, projverid, parentprojverids, compverid))
    #                 for parentprojverid in parentprojverids:
    #                     if projverid != parentprojverid:
    #                         comps = tempdf[tempdf.projverid == projverid].replace({projverid: parentprojverid},
    #                                                                               inplace=False)
    #                         # comps['projverid'] = parentprojverid
    #                         tempdf = pd.concat([tempdf, comps])
    #                         # tempdf.drop()
    #                         parentprojs += 1

    # Calculate mapping of projvers to compvers
    projcompmapdf = tempdf

    projcompmapdf = projcompmapdf.drop(
        ["projname", "projvername", "compid", "compname",
         "compvername", "seccritcount", "sechighcount", "secmedcount", "seclowcount", "secokcount",
         "lichighcount", "licmedcount", "liclowcount", "licokcount", "licname", ],
        axis=1, inplace=False)

    projdf = tempdf
    projdf["All"] = "All"

    projdf = pd.DataFrame(projdf.eval('secAll = seccritcount + sechighcount + secmedcount + seclowcount'))
    projdf = pd.DataFrame(projdf.eval('seccrithighcountplus1 = seccritcount + sechighcount + 1'))
    projdf = pd.DataFrame(projdf.eval('seccritcountplus1 = seccritcount + 1'))
    projdf = pd.DataFrame(projdf.eval('lichighcountplus1 = lichighcount + 1'))

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

    print("Found {} projects within {} projects".format(comps_as_projs, comps_as_projs_parents))

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

    # compdf = tempdf
    # remove duplicates
    compdf = tempdf.drop_duplicates(subset="compverid", keep="first", inplace=False)

    # sort by license risk
    compdf = compdf.sort_values(by=['lichighcount', 'licmedcount', 'liclowcount'], ascending=False)
    # Calculate license risk value as licrisk
    compdf['licrisk'] = compdf.apply(calc_license, axis=1)
    compdf = compdf.drop(["projname", "projvername", "projverid", "projverdist", "projverphase", "projtier"],
                         axis=1, inplace=False)

    compdf = compdf.sort_values(by=['compname'], ascending=True)

    def calc_lic_nounknown(row):
        if row['licname'] == 'Unknown License':
            return 1
        else:
            return 0

    compdf['licriskNoUnk'] = compdf.apply(calc_lic_nounknown, axis=1)

    projcompmapdf = projcompmapdf.sort_values(by=['projverid', 'compverid'], ascending=False)

    print('{} Components and {} Component Versions returned'.format(compdf.compname.nunique(),
                                                                    compdf.compverid.nunique()))

    return projdf, compdf, projcompmapdf


def proc_licdata(thisdf):
    licnames = thisdf.licname.values
    compids = thisdf.compverid.values
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

    vulndf = thisdf
    projvulnmapdf = thisdf
    compvulnmapdf = thisdf

    vuln_active_list = vulndf[vulndf['remstatus'].isin(['NEW', 'NEEDS_REVIEW', 'REMEDIATION_REQUIRED'])].vulnid.unique()
    # vuln_inactive_list = vulndf[~vulndf['remstatus'].isin(['NEW', 'NEEDS_REVIEW',
    #                                                          'REMEDIATION_REQUIRED'])].vulnid.unique()

    vulndf = vulndf.drop_duplicates(subset=["vulnid"], keep="first", inplace=False)
    vulndf = vulndf.sort_values(by=['score'], ascending=False)
    vulndf = vulndf.drop(["projname", "projvername", "compname", "compid", "compverid",
                          "compvername", "remstatus"],
                         axis=1, inplace=False)

    projvulnmapdf = projvulnmapdf.drop(["projname", "projvername", "compname", "compid", "compverid",
                                        "compvername", "relatedvulnid", "vulnsource", "severity", "score",
                                        "remstatus", "solution", "workaround", "pubdate", "description"],
                                       axis=1, inplace=False)
    compvulnmapdf = compvulnmapdf.drop(["projverid", "projname", "projvername", "compname", "compid",
                                        "compvername", "relatedvulnid", "vulnsource", "severity", "score",
                                        "remstatus", "solution", "workaround", "pubdate", "description"],
                                       axis=1, inplace=False)

    print('{} Vulnerabilities returned'.format(vulndf.vulnid.nunique()))
    return vulndf, projvulnmapdf, compvulnmapdf, vuln_active_list


def proc_pol_data(thisdf):
    projpolmap = thisdf
    comppolmap = thisdf

    projpolmap = projpolmap.drop(["compverid", "polname", "polstatus", "overrideby", "desc", "severity"],
                                 axis=1, inplace=False)
    comppolmap = comppolmap.drop(["projverid", "polname", "polstatus", "overrideby", "desc", "severity"],
                                 axis=1, inplace=False)


    thisdf = thisdf.drop_duplicates(subset=["polid"], keep="first", inplace=False)

    print('{} Policies returned'.format(thisdf.polid.nunique()))

    return thisdf, projpolmap, comppolmap


def proc_projinproj(projdf, compdf, projcompmapdf):
    projs_as_comps_dict = {}
    for index, row in projdf.iterrows():
        comp = compdf[compdf.compname == row['projname']]
        if row['projvername'] in comp.compvername.values:
            # Found project matching component
            foundcompverid = comp[comp.compvername == row['projvername']].compverid
            projs_as_comps_dict[row['projverid']] = foundcompverid
            # Copy components for projects within projects

            # for proj in projcompmapdf.projverid.values:

    print("Found {} projects within projects".format(len(projs_as_comps_dict)))
