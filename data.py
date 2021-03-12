import pandas as pd
import re


def proc_projdata(thisdf):
    newdf = thisdf
    newdf["All"] = "All"
    # Calculate total vulnerability count for all comps
    newdf = pd.DataFrame(newdf.eval('secAll = seccritcount + sechighcount + secmedcount + seclowcount'))
    newdf = pd.DataFrame(newdf.eval('secCrithighcountplus1 = seccritcount + sechighcount + 1'))
    newdf = pd.DataFrame(newdf.eval('seccritcountplus1 = seccritcount + 1'))
    newdf = pd.DataFrame(newdf.eval('lichighcountplus1 = lichighcount + 1'))

    # Sum columns for projVers
    sums = newdf.groupby("projverid").sum().reset_index()
    # Remove duplicate component rows
    newdf.drop_duplicates(subset="projverid", keep="first", inplace=True)
    # Count components in projvers
    df_counts = pd.DataFrame(thisdf['projverid'].value_counts(ascending=False).
                             rename_axis('projverid').reset_index(name='compcount'))

    # Merge compcount into df
    newdf = pd.merge(newdf, df_counts, on='projverid')
    # Remove duplicate and unwanted columns before merge
    newdf.drop(['secAll', 'secCrithighcountplus1', 'seccritcountplus1', 'lichighcountplus1',
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

    compdf = thisdf

    # sort by license risk
    compdf = compdf.sort_values(by=['lichighcount', 'licmedcount', 'liclowcount'], ascending=False)
    # remove duplicates
    compdf = compdf.drop_duplicates(subset="compverid", keep="first", inplace=False)

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

    # Calculate license risk value as licrisk
    compdf['licrisk'] = compdf.apply(calc_license, axis=1)
    # compdf = compdf.drop(["projname", "projvername", "projverid", "projverdist", "projverphase", "projtier"],
    #                      axis=1, inplace=False)

    compdf = compdf.sort_values(by=['compname'], ascending=True)

    def calc_lic_nounknown(row):
        if row['licname'] == 'Unknown License':
            return 1
        else:
            return 0

    compdf['licriskNoUnk'] = compdf.apply(calc_lic_nounknown, axis=1)
    # Calculate mapping of projvers to compvers
    projcompmapdf = thisdf

    projcompmapdf = projcompmapdf.drop(
        ["projname", "projvername", "compid", "compname",
         "compvername", "seccritcount", "sechighcount", "secmedcount", "seclowcount", "secokcount",
         "lichighcount", "licmedcount", "liclowcount", "licokcount", "licname", "All", ],
        axis=1, inplace=False)

    projcompmapdf = projcompmapdf.sort_values(by=['projverid', 'compverid'], ascending=False)

    print('{} Components and {} Component Versions returned'.format(compdf.compname.nunique(),
                                                                    compdf.compverid.nunique()))

    return compdf, projcompmapdf


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

    # vulndf = vulndf.drop_duplicates(subset=["vulnid"], keep="first", inplace=False)
    # vulndf = vulndf.sort_values(by=['score'], ascending=False)

    # projvulnmapdf = projvulnmapdf.drop(["projname", "projvername", "compname", " compid", "compverid",
    #                                     "compvername", "relatedvulnid", "vulnsource", "severity", "score",
    #                                     "remstatus", "solution", "workaround", "published_on", "desc"],
    #                                    axis=1, inplace=False)
    # compvulnmapdf = compvulnmapdf.drop(["projverid", "projname", "projvername", "compname", " compid",
    #                                     "compvername", "relatedvulnid", "vulnsource", "severity", "score",
    #                                     "remstatus", "solution", "workaround", "published_on", "desc"],
    #                                    axis=1, inplace=False)

    print('{} Vulnerabilities returned'.format(vulndf.vulnid.nunique()))

    return vulndf
