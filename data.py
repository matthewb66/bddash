import pandas as pd
import re


def proc_projdata(thisdf):
    newdf = thisdf
    newdf["All"] = "All"
    # Calculate total vulnerability count for all comps
    newdf = pd.DataFrame(newdf.eval('secAll = secCritCount + secHighCount + secMedCount + secLowCount'))
    newdf = pd.DataFrame(newdf.eval('secCritHighCountplus1 = secCritCount + secHighCount + 1'))
    newdf = pd.DataFrame(newdf.eval('secCritCountplus1 = secCritCount + 1'))
    newdf = pd.DataFrame(newdf.eval('licHighCountplus1 = licHighCount + 1'))

    # Sum columns for projVers
    sums = newdf.groupby("projVerId").sum().reset_index()
    # Remove duplicate component rows
    newdf.drop_duplicates(subset="projVerId", keep="first", inplace=True)
    # Count components in projvers
    df_counts = pd.DataFrame(thisdf['projVerId'].value_counts(ascending=False).
                             rename_axis('projVerId').reset_index(name='compCount'))

    # Merge compCount into df
    newdf = pd.merge(newdf, df_counts, on='projVerId')
    # Remove duplicate and unwanted columns before merge
    newdf.drop(['secAll', 'secCritHighCountplus1', 'secCritCountplus1', 'licHighCountplus1',
                'secCritCount', 'secHighCount', 'secMedCount',
                'secLowCount', 'secOkCount', 'licHighCount', 'licMedCount', 'licLowCount', 'licOkCount', 'compId',
                'compName', 'compVerId', 'compVerName', 'licName'], axis=1, inplace=True)
    # Merge sums into df
    newdf = pd.merge(newdf, sums, on='projVerId')
    print('{} Projects and {} Versions returned'.format(newdf.projName.nunique(), newdf.projVerId.nunique()))

    return newdf


def proc_comp_data(thisdf):
    # compdf will have 1 row per compver across all projvers
    # -  license risk will be the most severe across all projvers
    # projcompdf will have 1 row for each compver within each projver
    # - will map projVerId to compVerId

    compdf = thisdf

    # sort by license risk
    compdf = compdf.sort_values(by=['licHighCount', 'licMedCount', 'licLowCount'], ascending=False)
    # remove duplicates
    compdf = compdf.drop_duplicates(subset="compVerId", keep="first", inplace=False)

    def calc_license(row):
        if row['licHighCount'] > 0:
            return 'High'
        elif row['licMedCount'] > 0:
            return 'Medium'
        elif row['licLowCount'] > 0:
            return 'Low'
        elif row['licOkCount'] > 0:
            return 'OK'
        return ''

    # Calculate license risk value as licRisk
    compdf['licRisk'] = compdf.apply(calc_license, axis=1)
    compdf = compdf.drop(["projName", "projVerName", "projVerId", "projVerDist", "projVerPhase", "projTier"],
                         axis=1, inplace=False)

    compdf = compdf.sort_values(by=['compName'], ascending=True)

    def calc_lic_nounknown(row):
        if row['licName'] == 'Unknown License':
            return 1
        else:
            return 0

    compdf['licRiskNoUnk'] = compdf.apply(calc_lic_nounknown, axis=1)
    # Calculate mapping of projvers to compvers
    projcompmapdf = thisdf

    projcompmapdf = projcompmapdf.drop(
        ["projName", "projVerName", "projVerDist", "projVerPhase", "projTier", "compId", "compName",
         "compVerName", "secCritCount", "secHighCount", "secMedCount", "secLowCount", "secOkCount",
         "licHighCount", "licMedCount", "licLowCount", "licOkCount", "licName", "All", ],
        axis=1, inplace=False)

    projcompmapdf = projcompmapdf.sort_values(by=['projVerId', 'compVerId'], ascending=False)

    print('{} Components and {} Component Versions returned'.format(compdf.compName.nunique(),
                                                                    compdf.compVerId.nunique()))

    return compdf, projcompmapdf


def proc_licdata(thisdf):
    licnames = thisdf.licName.values
    compids = thisdf.compVerId.values
    # licrisks = thisdf.licRisk.values

    thislic_compverid_dict = {}  # Map of license names to compverids (dict of lists of compverids)
    thiscompverid_lic_dict = {}  # Map of compverids to licnames (dict of lists of licnames)
    # licrisk_dict = {}
    licname_list = []

    tempdf = thisdf
    sums = tempdf[~tempdf['licName'].str.startswith('(') &
                  ~tempdf['licName'].str.endswith(')')].groupby("licName").sum().reset_index()
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
            # lics = thisdf[thisdf['licName'] == item].licRisk.unique()
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
    #                                     licrisk_dict.values())), columns=['licName', 'licRisk'])
    # sorter = ['OK', 'Low', 'Medium', 'High']
    # temp_df.licRisk = temp_df.licRisk.astype("category")
    # temp_df.licRisk.cat.set_categories(sorter, inplace=True)
    return sums, thislic_compverid_dict, thiscompverid_lic_dict


def proc_vuln_data(thisdf):
    # vulndf will have 1 row per vulnId
    # projvulnmapdf will have 1 row for each vuln within each projver
    # - will map projVerId to compVerId

    vulndf = thisdf
    projvulnmapdf = thisdf
    compvulnmapdf = thisdf

    vulndf = vulndf.drop(["projVerId", "projName", "projVerName", "compName", "compId", "compVerId", "compVerName"],
                         axis=1, inplace=False)

    vulndf = vulndf.drop_duplicates(subset=["vulnId"], keep="first", inplace=False)
    vulndf = vulndf.sort_values(by=['score'], ascending=False)

    projvulnmapdf = projvulnmapdf.drop(["projName", "projVerName", "compName", "compId", "compVerId",
                                        "compVerName", "relatedVulnId", "vulnSource", "severity", "score",
                                        "remStatus", "solution", "workaround", "published_on", "desc"],
                                       axis=1, inplace=False)
    compvulnmapdf = compvulnmapdf.drop(["projVerId", "projName", "projVerName", "compName", "compId",
                                        "compVerName", "relatedVulnId", "vulnSource", "severity", "score",
                                        "remStatus", "solution", "workaround", "published_on", "desc"],
                                       axis=1, inplace=False)

    print('{} Vulnerabilities returned'.format(vulndf.vulnId.nunique()))

    return vulndf, projvulnmapdf, compvulnmapdf
