import streamlit as st
from lib.http_requests import fetch_url
from lib.security_headers import check_security_headers, analyze_cookies
from lib.directory_enumeration import directory_enumeration
from lib.injection_tests import test_sqli
from lib.content_analysis import analyze_content
from lib.authentication_tests import test_authentication
from lib.performance_tests import performance_test_menu
from lib.subdomain_discovery import run_subdomain_discovery
from front.SecHeadReport import display_security_report

# Page configuration
st.set_page_config(
    page_title="AppScan Intelliway",
    page_icon="favicon.ico",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS styling
st.markdown("""
<style>
[data-testid="stSidebar"] {
    background-color: #708090;
}
[data-testid="stHeader"] {
    background-color: transparent;
}
[data-testid="stToolbar"] {
    right: 2rem;
}
[data-testid="stVerticalBlock"] {
    margin-top: -2rem;
}
[data-testid="block-container"] {
    padding: 2rem;
}
[data-testid="stMarkdownContainer"] h1 {
    text-align: center;
    margin-bottom: 0.5rem;
}
[data-testid="stMarkdownContainer"] h2 {
    text-align: center;
    margin-top: 0;
}
.logo {
    display: block;
    margin-left: auto;
    margin-right: auto;
    width: 150px;  /* Ajuste o tamanho da logo conforme necessário */
    margin-bottom: 0.5rem;
}
</style>
""", unsafe_allow_html=True)

# Main function for Streamlit
def main():
    st.title("AppScan Intelliway")

    # Sidebar for inputs
    with st.sidebar:
        st.header("Scan Configuration")
        url = st.text_input("Enter the URL to scan", "https://example.com")
        st.write("Select the types of tests you want to perform:")
        check_security = st.checkbox("Check security headers")
        check_cookies = st.checkbox("Analyze cookies")
        check_directories = st.checkbox("Enumerate directories")
        check_sqli = st.checkbox("Test SQL Injection")
        check_content = st.checkbox("Analyze content")
        check_authentication = st.checkbox("Test authentication")
        check_performance = st.checkbox("Performance test")
        check_subdomains = st.checkbox("Discover subdomains")

        # Submission button
        run_scan = st.button("Run Scan")

    # Placeholder for results
    results_placeholder = st.empty()

    if run_scan:
        if not url:
            st.error("Please enter a valid URL.")
            return

        st.write(f"Running scans for {url}...")

        results = {}
        if check_security:
            response = fetch_url(url)
            if response:
                security_report = check_security_headers(response.headers, url)
                results["Security Headers"] = security_report

        if check_cookies:
            response = fetch_url(url)
            if response:
                results["Cookies"] = analyze_cookies(response.headers)

        if check_directories:
            st.write("Enumerating directories...")
            directory_enumeration(url)
            results["Directories"] = "Directory enumeration completed."

        if check_sqli:
            st.write("Testing SQL Injection...")
            test_sqli(url)
            results["SQL Injection"] = "SQL Injection test completed."

        if check_content:
            response = fetch_url(url)
            if response:
                st.write("Analyzing content...")
                content_results = analyze_content(response.text)
                results["Content"] = content_results

        if check_authentication:
            st.write("Testing authentication...")
            test_authentication(url)
            results["Authentication"] = "Authentication test completed."

        if check_performance:
            st.write("Testing performance...")
            performance_test_menu(url)
            results["Performance"] = "Performance test completed."

        if check_subdomains:
            st.write("Discovering subdomains...")
            subdomain_results = run_subdomain_discovery(url)
            results["Subdomains"] = subdomain_results

        # Display results on the main screen
        results_placeholder.write("## Scan Results")
        for key, value in results.items():
            results_placeholder.write(f"### {key}")
            if key == "Security Headers":
                display_security_report(value)
            else:
                results_placeholder.write(value)


if __name__ == "__main__":
    main()
