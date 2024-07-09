import streamlit as st

# Adicionando CSS para as cores das notas
st.markdown("""
<style>
.reportSection {
    margin: 20px 0;
}
.reportTitle {
    font-size: 24px;
    margin-bottom: 10px;
}
.reportBody {
    padding: 10px;
    background-color: #f9f9f9;
    border: 1px solid #ddd;
}
.tableLabel {
    font-weight: bold;
}
.table_red {
    color: red;
}
.table_orange {
    color: orange;
}
.table_yellow {
    color: yellow;
}
.table_light_green {
    color: lightgreen;
}
.table_green {
    color: green;
}
.score {
    text-align: center;
    font-size: 40px;
    font-weight: bold;
}
.score_A {
    color: green;
}
.score_B {
    color: lightgreen;
}
.score_C {
    color: yellow;
}
.score_D {
    color: orange;
}
.score_F {
    color: red;
}
</style>
""", unsafe_allow_html=True)

def display_security_report(report):
    st.write("## Security Report Summary")

    grade = report['Security Report Summary']
    site = report['Site']
    ip_address = report['IP Address']
    report_time = report['Report Time']
    headers = report['Headers']
    advanced = report['Advanced'][list(report['Advanced'].keys())[0]]
    missing_headers = advanced["Missing Headers"]
    cookie_issues = advanced["Cookie Analysis"]["issues"]
    raw_headers = report["Raw Headers"]

    # Define a cor da nota com base na graduação
    grade_color_class = {
        "A+": "score_A",
        "A": "score_A",
        "B": "score_B",
        "C": "score_C",
        "D": "score_D",
        "E": "score_D",
        "F": "score_F"
    }.get(grade, "score_F")

    # Security Report Summary Section
    st.markdown(f"""
    <div class="reportSection">
        <div class="reportBody">
            <div class="row">
                <div class="10u push-left">
                    <table class="reportTable">
                        <colgroup>
                            <col class="col1">
                            <col class="col2">
                        </colgroup>
                        <tbody>
                            <tr class="tableRow">
                                <th class="tableLabel">Grade:</th>
                                <td class="tableCell">{grade}</td>
                            </tr>
                            <tr class="tableRow">
                                <th class="tableLabel">Site:</th>
                                <td class="tableCell"><a href="{site}" target="_blank" rel="nofollow noreferrer noopener">{site}</a></td>
                            </tr>
                            <tr class="tableRow">
                                <th class="tableLabel">IP Address:</th>
                                <td class="tableCell">{ip_address}</td>
                            </tr>
                            <tr class="tableRow">
                                <th class="tableLabel">Report Time:</th>
                                <td class="tableCell">{report_time}</td>
                            </tr>
                            <tr class="tableRow">
                                <th class="tableLabel">Headers:</th>
                                <td class="tableCell">
                                    <ul class="pillList">
                                        {''.join([f'<li class="headerItem pill pill-green"><i class="fa fa-check"></i>{header}</li>' if header.lower() in raw_headers else f'<li class="headerItem pill pill-red"><i class="fa fa-times"></i>{header}</li>' for header in headers])}
                                    </ul>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Missing Headers Section
    st.markdown("""
    <div class="reportSection">
        <div class="reportTitle">Missing Headers</div>
        <div class="reportBody">
            <table class="reportTable">
                <colgroup>
                    <col class="col1">
                    <col class="col2">
                </colgroup>
                <tbody>
                    {missing_headers_rows}
                </tbody>
            </table>
        </div>
    </div>
    """.format(
        missing_headers_rows=''.join([
            f'<tr class="tableRow"><th class="tableLabel table_red">{header}</th><td class="tableCell">{get_header_description(header)}</td></tr>'
            for header in missing_headers])
    ), unsafe_allow_html=True)

    # Raw Headers Section
    st.markdown("""
    <div class="reportSection">
        <div class="reportTitle">Raw Headers</div>
        <div class="reportBody">
            <table class="reportTable">
                <colgroup>
                    <col class="col1">
                    <col class="col2">
                </colgroup>
                <tbody>
                    {raw_headers_rows}
                </tbody>
            </table>
        </div>
    </div>
    """.format(
        raw_headers_rows=''.join(
            [f'<tr class="tableRow"><th class="tableLabel">{header}</th><td class="tableCell">{value}</td></tr>' for
             header, value in raw_headers.items()])
    ), unsafe_allow_html=True)

def get_header_description(header):
    descriptions = {
        "Content-Security-Policy": '<a href="https://scotthelme.co.uk/content-security-policy-an-introduction/" target="_blank">Content Security Policy</a> is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets.',
        "X-Frame-Options": '<a href="https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options" target="_blank">X-Frame-Options</a> tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking. Recommended value "X-Frame-Options: SAMEORIGIN".',
        "Referrer-Policy": '<a href="https://scotthelme.co.uk/a-new-security-header-referrer-policy/" target="_blank">Referrer Policy</a> is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.',
        "Permissions-Policy": '<a href="https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/" target="_blank">Permissions Policy</a> is a new header that allows a site to control which features and APIs can be used in the browser.'
    }
    return descriptions.get(header, '')
