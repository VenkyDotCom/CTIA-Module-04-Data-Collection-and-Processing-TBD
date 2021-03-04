# Module 04: Data Collection and Processing

## Objective

The objective of this lab is to perform:

- Data collection
- Data processing
- Data visualization

## Scenario

Threat intelligence collection is a continuous process which involves acquisition and triage of usable data to extract the true intelligence. Analysts can collect the threat data either from multiple teams in an organization like network security teams, penetration testing teams, web application security teams, etc. or by conducting the threat intelligence collection manually. An analyst must be aware of working both in collaboration with teams or work individually in gathering the threat information. Data Collection is the crucial step for building effective threat intelligence and before collecting data, analyst must know that the information that he/she should gather can be anything related to the organization or industry for which he/she is building the threat intelligence and this information can include details like threats, threat actors, malware, malware campaigns, etc. or it can also include organizational details, vulnerabilities and security loopholes in organizational infrastructure, etc. The analyst must gather every possible information that can pose a threat to the organization. After gathering the information, an analyst must be able to structure the unstructured data to extract intelligence from the data. An analyst must be able to know various tricks and techniques in processing the huge data that is collected into a structured form and visualize the data accordingly. This structured data will be decimated to perform an analysis where the true intelligence will be extracted using various analysis techniques. In this module, we shall discuss various threat intelligence data collection and processing techniques that can be employed \(and not limited to\) for building effective threat intelligence.

---

# Exercise 1: Data Collection through Search Engines

## Scenario

Search engines are one of the information sources to locate key information about threats and vulnerability scenarios. Search engines play a major role in extracting critical details about a target from the Internet. It returns a list of Search Engine Results Pages \(&lsquo;SERPs&rsquo;\). Threat analysts and security professionals use search engines to extract information about target threats and threat actors such as industry threats, technology threats, exploit used, exploit delivery method, harm caused, etc. which help them in analyzing the impact of the threat to the organization. These search engines can also be used by the analyst to gather organizational information from an attacker point-of-view which helps in identifying the loopholes or vulnerabilities in the organization infrastructure.   
Dark web is the internet space that is not indexed. It is the place where all active hacker and threat actors operate. The dark web cannot be accessed easily by traditional browsers and search engines. The analyst can acquire large amounts of data related to the threat by performing dark web searching using dedicated deep and dark web search engines and browsers.  
  
**Lab Scenario**

An easy way to find threats and vulnerabilities in websites and applications is to Google them or use other search engines, which is a simple method adopted by attackers. Using search engines, hackers can identify crucial vulnerabilities in application code strings, providing the entry point they need to break through application security. As an analyst, you should use the same methods used by the hackers such as data collection using search engines to collect the data regarding all the existing vulnerabilities in the organizational infrastructure and patch them before an attacker identifies them to exploit vulnerabilities. Also, an analyst has to collect the threat information that is not available on the surface web. To do this, an analyst has to perform various deep and dark web searching techniques to collect information that can be helpful in conducting threat analysis and intelligence building process.  
  
**Lab Objectives**

The objective of this lab is to demonstrate:  

- Open source intelligence gathering using Google Hacking Database
- Open source intelligence gathering using ThreatCrowd
- Open source intelligence gathering by deep and dark web searching using Tor Browser

Lab Duration: **25 Minutes**  

1. By default, **Windows 10** machine is selected click **Ctrl+Alt+Delete**.

	![](./1078435.jpg)

1. In the Password field type **Pa$$w0rd** and press **Enter** to login.

	>Note: If **Networks** prompt appears once you have logged into the machine, click **Yes**.

	![](./1078436.jpg)

1. Launch any browser, in this lab, we are using the Mozilla Firefox browser. Double-click **Firefox** shortcut icon on the desktop.

	![](./1078437.jpg)

1. In the address bar of the browser type **https://www.exploit-db.com/google-hacking-database** and press **Enter**. Google Hacking Database \(GHDB\) page appears.  
	  
	Scroll down the page and review the latest entries. These are entries that have been discovered and submitted by the community. Take a few minutes and click on a few of them and see what you can discover. As you can see, these links can display quite a bit of information. Some of them may fail because the queries have been discovered, but you should be able to find valuable information when you are doing your testing.

1. Click **Filters**.

	![](./pzvk4p4i.jpg)

1. Click the drop-down menu in **Category** field to view the existing categories. Select **Footholds** category from the drop-down menu in Category field.

1. This will redirect you to the **Footholds** search results. What you would do in your testing is to create files of these queries. Then, with written **authorization** and **permission** to test the organizational site, you would use the string and enter the site that you are testing to see if there are any foothold weaknesses in the site. The foothold links are shown in the screenshot.

	![](./jcgphnhz.jpg)

1. After you have reviewed the entries, select **Vulnerable Files** from the **Category** drop-down menu. In the vulnerable files results, there is a query that says **&ldquo;allinurl:forcedownload.php?file=&rdquo;**.

	>Note: The screenshots and search query results may vary in your environment, you may choose a query of your own and explore.

	![](./bh0bpygv.jpg)

1. This query locates sites that use the **forcedownload.php** script and are vulnerable to URL manipulation. The site will spit out any file on the local site, including the **PHP files**, with all **server-side** code. We are not talking about the rendered page, but the source itself. This is most commonly used on **WordPress** sites to grab the **wp-config.php** file to gain access to the database but is not limited to WordPress sites. Many queries exist like this, and you are encouraged to develop your own and test whether the organization site is vulnerable.

	![](./1r3zvh31.jpg)

1. Now, open a new tab in the Firefox browser and open google.com. In the Google search type **allinurl:forcedownload.php?file=** and click **Google Search**. An example of Google search result of the above-mentioned query can be found in the screenshot. **Close** the New tab in the browser window.

	![](./r3idrjgr.jpg)

1. In the Google Hacking Database landing page and the next item, we want to check out is the vulnerable servers, select **Vulnerable Servers** from the **Category**. You will get the queries related to vulnerable servers.

	![](./boppaqo1.jpg)

1. Once again, there are a number of queries we can use to identify potentially vulnerable servers. For example, we will look at the query **filetype:php inurl:tiki-index.php \+sirius \+1.9.\***.

	>Note: The screenshots and search query results may vary in your environment, you may choose a query of your own and explore.

	![](./btdpz0v2.jpg)

1. Open a new tab in the browser and open google.com. In the google.com search field type **filetype:php inurl:tiki-index.php \+sirius \+1.9.\*** and click **Google Search** button. This query will look for the tiki-graph\_formula.php in TikiWiki 1.9.8 that allows remote attackers to execute arbitrary code via PHP sequences in the array parameter, which are processed by create\_function. The following screenshot shows the results of this query. This is vulnerability **CVE-2007-5423**, even though it is from 2007, it can still be found today. This is part of our testing methodology, we identify the potential vulnerabilities and then go from there. The powerful cloud scanners that are out there makes it much easier for the tester.

	![](./0vjhwzth.jpg)

1. Switch back to the Google Hacking Database landing page and the next item we are going to check out is the files containing the password, select **Files Containing Passwords** from the **Category** drop-down menu. You will get the queries related to files containing passwords. For example, we will look at the query "**password.xlsx" ext:xlsx**.

	>Note: The screenshots and search query results may vary in your environment, you may choose a query of your own and explore.

	![](./1pazy1kp.jpg)

1. Switch to the new tab window and in the Google search field type **"password.xlsx&rdquo; ext: xlsx** and click **Google Search** icon. The query **&ldquo;password.xlsx&rdquo; ext:xlsx** result in Google search clearly shows the links of documents and files containing passwords and user data which are accessible without any restrictions. Ensure the organization is secure and without any such vulnerabilities. The following screenshot shows the results of this query.

	![](./a2ulyinm.jpg)

1. Switch back to the **Google Hacking Database landing page** and the last one we will look at is the login portals query, select **Pages Containing Login Portals** from the **Category**. Locate and search the query **inurl:login.jsp intitle:"admin"** in **Google Search**. This will display any pages that still have the default admin password set.

	>Note: The screenshots and search query results may vary in your environment, you may choose a query of your own and explore.

	![](./r2d2trcg.jpg)

1. Click on any one of the links to view the **jsp admin websites**. \(Here, we selected **https://www.instantreg.com/eregistration/login.jsp**\). Ensure that the organizational website does not contain such vulnerability. This concludes the demonstration of open source intelligence gathering using the **Google Hacking Database**. You can conduct a series of queries and review the information related to the threats concerning the organization from the Google hacking site. You can document all the acquired information. Open a new tab and close all the old tabs.

	![](./3bfev5aj.jpg)

1. Now, we shall perform the open source intelligence gathering using ThreatCrowd. In the new tab window type **https://www.threatcrowd.org** in the address bar and press **Enter**. A Search Engine for Threats page appears as shown in the screenshot. In the search field, type the organization&rsquo;s URL that you wish to analyse \(here, **www.certifiedhacker.com**\) and click **SEARCH NOW &gt;**.

	![](./1079096.jpg)

1. You can see the detailed information regarding the provided URL such as **IP address**, **name servers**, **DNS resolutions**, **WhoIs results**, etc. These details are present in the public domain and are important for the analyst to gather such information that can pose a threat. This concludes the demonstration of open source intelligence gathering using ThreatCrowd. You can conduct a series of queries and gather publicly available organizational information from the ThreatCrowd site. You can document all the acquired information. Close the browser window.

	![](./1079097.jpg)

1. Now, we shall perform the open source intelligence gathering by **deep and dark web searching using Tor Browser**. Open a **File Explorer** and navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Tor Browser** and double-click **torbrowser-install-7.5.5\_en-US.exe**.  
	  
	Installer Language window appears, select your preferred language \(here, **English**\) and click **OK**.

	>Note: If Open File &ndash; Security Warning window appears, click **Run**. If the User Account Control pop-up appears, click **Yes**.

	![](./1079098.jpg)

1. Follow the wizard steps \(by selecting default options\) to install **Tor Browser**. After the installation is complete, click **Finish** button to complete the installation and launch the **Tor Browser** as shown in the screenshot.

	>Note: Make sure that **Run Tor Browser** option is checked.

	![](./1079099.jpg)

1. Connect to Tor window appears. Click **Connect** button to browse through Tor browser default settings directly.

	>Note: If Tor is censored in your country or if you want to connect through Proxy, click **Configure** button here and continue. It will take a **maximum** of **5** minutes to launch the Tor Browser.

	![](./1079100.png)

1. After a few second, Tor browser home page appears. The main advantage of the Tor browser is that it maintains the anonymity of the user throughout the session. To test the anonymity of the user, click on the **Test Tor Network** **Settings** link in the tor browser home page as shown in the screenshot.

	![](./1079101.jpg)

1. You can see that your session is working with the IP address **93.115.86.9**. This IP address is selected randomly by Tor and attributing user from this IP address is literally impossible. After verifying and ensuring the anonymity, you can navigate back to the tor browser&rsquo;s home page. Minimize the Tor Browser.

	>Note: The IP address will vary in your environment. And, this public IP address changes each time you re-open Tor browser.

	![](./1079102.jpg)

1. As an analyst, your job is to collect as much as information related to the threats from the dark web. Before doing that, you must know the actual difference between **surface web searching** and **dark web searching**. Open **Google Chrome**. Navigate to **www.google.com** and in **Google search**, search for information related to the **hacker for hire**. You will be loaded with large amounts of irrelevant data as shown in the screenshot.

	![](./1079103.jpg)

1. Now switch to Tor browser and search for the same \(i.e., **hacker for hire**\). You will find the relevant links related to the professional hackers who operate underground through the dark web. Click and open any of the search results \(here, **hackerforhire.com**\). 

	>Note: The search result may vary in your environment. Tor uses **DuckDuckGo** search engine to perform a dark web search. The result may vary in your environment.

	![](./1079104.jpg)

1. The hackerforhire.com web page opens up as shown in the screenshot and you can see that the site belongs to professional hackers who operate underground. This information related to professional hackers and hacking services can be used to build effective threat intelligence.

	>Note: If **LEARN HOW TO BECOME HACKER** pop-up appears close the pop-up.

	![](./1079105.jpg)

1. A dark web search for threat intelligence analysts does not stop with hackerforhire.com. The analyst can collect large amounts of threat information from multiple dark web searches.  
	  
	The analyst can also explore the following onion sites using Tor Brower to gather relevant threat information anonymously that can be used to develop organizational threat intelligence.  
	
	- The Hidden Wiki on .onion \(http://zqktlwi4fecvo6ri.onion/wiki/index.php/Main\_Page\)
	- Facebook&rsquo;s .onion site \(https://www.facebookcorewwwi.onion/\)
	- Netpoleaks is the .onion police monitor \(http://owmx2uvjkmdgsap2.onion/\)
	- Keybase is the cryptographic profile link system \(http://fncuwbiisyh6ak3i.onion\)
	
	This concludes the demonstration of open source intelligence gathering by deep and dark web searching using Tor Browser. You can document all the acquired information. This concludes the lab exercise, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

In this exercise, you have learnt how to perform:  

- Open source intelligence gathering using Google Hacking Database
- Open source intelligence gathering using ThreatCrowd
- Open source intelligence gathering by deep and dark web searching using Tor Browser

---

# Exercise 2: Data Collection through Web Services

## Scenario

Web services such as people search, domain search services can provide sensitive information about the target. Internet archives may also provide sensitive information that has been removed from the World Wide Web \(&lsquo;WWW&rsquo;\). Social networking sites, people search services, alerting services, financial services, and job sites provide information about a target organization such as infrastructure details, physical location, and employee details, etc. Moreover, groups, forums, and blogs can help in gathering sensitive information about a target such as public network information, system information, and personal information. Some web services also offer crucial information about the organizational domains and subdomain information that can be accessible only by authorized personnel to the attackers. Web services are also capable of identifying whitelisted and blacklisted websites. Using this information, an analyst can analyze the vulnerabilities and threats in the organization.  

**Lab Scenario** 

In the process of data collection, your next task will be to use web services to extract information regarding the organization. You are required to use various open source web services to gather useful information like domains, sub-domains, etc. from the organizational website. You must also be capable of checking whether the website is considered as blacklist by any sources \(or\) you must be capable of collecting blacklisted and whitelisted websites information to build threat intelligence. This lab will show you how to extract the domain and subdomain information using Netcraft and also shows how to collect blacklisted and whitelisted website information using Apility.io.  
  
**Lab Objectives**

The objective of this lab is to demonstrate:  

- Finding Top-level Domains \(TLDs\) and Sub-domains using Netcraft
- Data Collection related to Blacklisted and Whitelisted Sites using Apility.io

Lab Duration: **10 Minutes**

1. By default, **Windows 10** machine is selected click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the Windows 10 machine then skip to step **3**.

	![](./1079107.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If Networks prompt appears once you have logged into the machine, click **Yes**.

	![](./1079108.jpg)

1. Launch any browser, in this lab, we are using the Google Chrome browser. Double-click **Google Chrome** shortcut icon on the desktop.

	![](./1079109.jpg)

1. In the address bar of the browser type **https://www.netcraft.com** and press **Enter**. Netcraft homepage appears as shown in the screenshot.

	![](./1079110.jpg)

1. In order to extract information associated with the organizational website such as Site title, Site rank, Risk rating, etc. type the target website&rsquo;s URL \(here, **www.certifiedhacker.com**\) in the text field present below **What&rsquo;s that site running?** in the right pane and then click on the **Search Icon** (**--&gt;**).

	![](./1079111.jpg)

1. A site report containing information related to **Background**, **Network**, **Hosting History**, etc. of the target website is displayed as shown in the screenshot.  
	  
	Using the result obtained from Netcraft tool, an analyst can determine the amount of information regarding the organizational website available publicly, which can be used by adversaries to exploit the website and further launch an attack on the target organization. However, using this information, the analyst can take certain steps to allow only limited information about the website to the public. This concludes the demonstration of website data collection using Netcraft tool. You can document all the acquired information.

	![](./1079112.jpg)

1. Now, we shall perform the data collection related to **blacklisted** and **whitelisted** sites using **Apility.io**. Open a new tab in the google chrome browser and close the Netcraft tab. In the address bar of the browser type **https://www.apility.io** and press **Enter**. The **apility.io** website appears, as shown in the screenshot.

	>Note: Close all the pop-ups that appear.

	![](./1079113.jpg)

1. To determine if the target website is blacklisted or not, type the target website URL \(here, **www.certifiedhacker.com**\) in the search now field and then click on **SEARCH NOW!** button.

	![](./1079114.jpg)

1. A site report regarding blacklist will be generated which contains scores with respect to different blacklisting criteria \(Negative score is assigned to high-risk domains, positive score means the domain is trustable, and a zero value is neutral, which means you must analyze each individual score as a safety measure\).  
	  
	Using the result obtained from the apility.io tool, an analyst can determine whether the website is blacklisted or whitelisted. Using this information, the analyst can block blacklisted URL from the organizational network. So, such websites cannot be used by the adversaries to launch an attack on the organization. This concludes the demonstration of data collection related to blacklisted and whitelisted sites using Apility.io. This concludes the lab exercise, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1079115.jpg)

In this exercise, you have learnt how to:  

- Find Top-level Domains \(TLDs\) and Sub-domains using Netcraft
- Data Collection related to Blacklisted and Whitelisted Sites using Apility.io

---

# Exercise 3: Data Collection through Website Footprinting

## Scenario

Website footprinting refers to the reconnaissance or in-depth analysis of the website source code and the components to extract valuable information regarding the organization. It is possible for an attacker to build a detailed map of a website's structure and architecture without triggering the IDS or without raising any system administrator&rsquo;s suspicions. Attackers these days&rsquo; use sophisticated footprinting tools to perform the website footprinting and gather crucial information. In order to analyze the threat that an attacker can pose, an analyst must first understand what information an attacker can acquire by performing website footprinting.  
  
**Lab Scenario**  

In the process of data collection, your next task will be to extract information from the organization website. You are required to perform website footprinting to gather useful information like software used and its version, source code, Operating system used, sub-directories and parameters, metadata, etc. from the website. This lab will show you how to mirror a website and view the source code of the website offline and also shows you to perform metadata extraction of public documents on the target website.  
  
**Lab Objectives**  
  
The objective of this lab is to demonstrate:  

- Data Collection by Mirroring the Organizational Website using HTTrack Website Copier
- Organizational Website Metadata Extraction using Web Data Extractor

  
Lab Duration: **10 Minutes**

1. By default, **Windows 10** machine is selected click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the Windows 10 machine then skip to step **3**.

	![](./1079116.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If Networks prompt appears once you have logged into the machine, click **Yes**.

	![](./1079117.jpg)

1. To install HTTrack Website Copier, open a File Explorer window and navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\HTTrack Website Copier** and double-click **httrack\_x64-3.49.2.exe**.  
	  
	Follow the wizard steps to install HTTrack Web Site Copier.

	>Note: If the User Account Control pop-up appears, click **Yes**.

	![](./1079118.jpg)

1. In the last step of the installation wizard, uncheck **View history.txt** file option and click **Finish**.

	![](./1079119.jpg)

1. The WinHTTrack Website Copier main window appears. Click **OK** and then click **Next** to create a **New Project**.

	>Note: If the application does not launch, you can launch it manually from the Apps screen.

	![](./1079120.jpg)

1. Enter the name of the project in the Project name field. Select the **Base path** to store the copied files. Click **Next**.

	>Note: If the project is new then the Project name field changes to the New project name.

	![](./1079121.jpg)

1. Enter **www.certifiedhacker.com** in the **Web Addresses**: \(URL\) field and click **Set options&hellip;**.

	![](./1079122.jpg)

1. In the WinHTTrack window, click the **Scan Rules** tab and select the check boxes for the file types as shown in the screenshot, then click **OK**.

	![](./1079123.jpg)

1. Click **Next** after providing all the options.

	![](./1079124.jpg)

1. By default, the radio button will be selected for &ldquo;**Please adjust connection parameters if necessary**, **then press** **FINISH** to **launch the mirroring operation**.&rdquo;. Check **Disconnect when finished check box** and click **Finish** to start mirroring the website.

	![](./1079125.jpg)

1. **Site mirroring** progress will be displayed as in the screenshot.

	>Note: Some websites are very large and it might take a long time to mirror the complete site. If you wish to stop the mirroring in progress, Click Cancel on the Site mirroring progress window.

	![](./1079126.jpg)

1. WinHTTrack displays the message Mirroring operation complete once the site mirroring is completed. Click **Browse Mirrored Website**.

	![](./1079127.jpg)

1. How do you want to open this file? the pop-up appears, choose **Google chrome** and click **OK**.

	![](./1079128.jpg)

1. The mirrored website for www.certifiedhacker.com launches. The URL displayed in the address bar indicates that the website's image is stored on the local machine. The site will work like a live hosted website.  

	>Note: If the webpage does not open, navigate to the directory where you mirrored the website and open index.html with any browser.

	![](./1079129.jpg)

1. In order to view the source code of the webpage, right-click on the website page and select **View page source**.

	![](./1079130.jpg)

1. Browse the source code of the index page opened in the new tab of the browser window. Notice that the source code contains important information about the websites such as linked web URLs and website metadata.

	![](./1079131.jpg)

1. The website directory structure present in **C:\\My Web Sites\\Test Project\\www.certifiedhacker.com** reveals the files used in the website construction, including its design CSS, images, and JavaScript code files. This data can be used for extracting important information about the website. Analysts can use this information to identify and secure the vulnerabilities that this data can create.  
	  
	This concludes the demonstration of data collection by mirroring the organizational website using HTTrack Website Copier. You can document all the acquired information. Close all the open Windows.

	![](./1079132.jpg)

1. Now, we shall perform the organizational website metadata extraction using Web Data Extractor. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Web Data Extractor** and double-click **wde.exe**.  
	  
	Follow the wizard steps to install Web Data Extractor.

	>Note: If the User Account Control pop-up appears, click **Yes**.

	![](./1079336.jpg)

1. In the completion page, check the **Launch Web Data Extractor** checkbox present at the left bottom of the window and click **Finish**.

	![](./1079337.jpg)

1. Web Data Extractor 8.3 window appears. Click **New** to start a new session.

	![](./1079338.jpg)

1. Session settings window appear, type a URL (**http://www.certifiedhacker.com**) in the Starting URL field. Check all the options as shown in the screenshot, and click **OK**.

	![](./1079339.jpg)

1. Click **Start** to initiate the Data Extraction.

	![](./1079340.jpg)

1. Web Data Extractor will start collecting information such as emails, Phones, Faxes, etc. from the provided URL of the target web page.

	![](./1079341.jpg)

1. Once the data extraction process is completed, an Information dialogue box appears. Click **OK**.

	![](./1079342.jpg)

1. To examine the collected data, view the extracted information by clicking the tabs.

	![](./1079343.jpg)

1. Select **Meta tags** tab to view the URL, title, keywords, description, host, domain, etc.

	![](./1079344.jpg)

1. Select the **Emails tab** to view the email address, name, URL, Title, host, keywords density, etc. information related to emails.

	![](./1079345.jpg)

1. Select the **Phones** tab to view the phone number, source, tag, etc. Check for more information under the Faxes, Merged list, URLs, and Inactive sites tabs.

	![](./1079346.jpg)

1. To save the session, choose **File** and click **Save session**.

	![](./1079347.jpg)

1. Specify the session name in the Save session the dialog box and click **OK**.

	![](./1079348.jpg)

1. Click the **Meta tags** tab and then click the **floppy** icon.

	![](./1079349.jpg)

1. 5. An Information pop-up may appear with the message; You cannot save more than 10 records in the Demo version. Click **OK**.

	![](./1079350.jpg)

1. Select the Location and File format and click **Save**. By default, the session will be saved at **C:\\Program Files \(x86\)\\**  
	**WebExtractor\\Data\\certifiedhacker.com**. You can save information gathered related to the organization from the Meta Tags, Emails, Phones, Faxes, Merged list, URLs and Inactive sites tabs.  
	  
	This concludes the demonstration of organizational website metadata extraction using Web Data Extractor. You can document all the acquired information. This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1079351.jpg)

In this exercise, you have learnt how to:  

- Data Collection by Mirroring the Organizational Website using HTTrack Website Copier
- Organizational Website Metadata Extraction using Web Data Extractor

---

# Exercise 4: Data Collection through Email Footprinting

## Scenario

Email tracking or e-mail footprinting monitor the emails of a particular user. This kind of tracking is possible through digitally time-stamped records that reveal the time and date when the target receives and opens a specific email. Email tracking tools allow an analyst to collect information such as IP addresses, mail servers, and service provider involved in sending the mail. Analysts can use this information to identify the presence of social engineering and other attacks and build a defence strategy to protect the organization from such attacks.  
E-mail tracking is a method to monitor or spy on email delivered to the intended recipient. It reveals information such as:  

- When an email message was received and read
- If a destructive email was sent
- The GPS coordinates and map location of the recipient
- The time spent reading the email
- Whether or not the recipient visited any links sent in the email
- PDFs and other types of attachments
- If messages were set to expire after a specified time

**Lab Scenario**  
  
Attackers or threat actors may send malicious emails to a victim \(employee\) of an organization to attack a target organization. In the process of data collection, your next task will be to extract the threat actor&rsquo;s information by tracing out such malicious emails. Tracing emails involves analyzing the email header to discover details about the sender. You are required to perform email footprinting and gather useful information like when the email was received or opened, geographical information, network ISP, domain Whois information, etc.  
  
**Lab Objectives** 

The objective of this lab is to demonstrate:  

- Data Collection by Tracking Email Communications using eMailTrackerPro

Lab Duration: **10 Minutes**

1. By default, **Windows 10** machine is selected click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the Windows 10 machine then skip to step **3**.

	![](./1079352.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If Networks prompt appears once you have logged into the machine, click **Yes**.

	![](./1079353.jpg)

1. To install eMailTrackerPro, navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\eMailTrackerPro** and double-click **emt.exe** installer file.  
	  
	Follow the wizard steps \(by selecting default options\) to install eMailTrackerPro.

	>Note: If the User Account Control pop-up appears, click **Yes**. If there is any error while installation because of java, you can navigate to D:\\CTIA-Tools\\CTIA Lab Prerequisites\\Java Runtime Environment folder and double-click jre-8u171-windows-i586.exe to install the Java software in your machine. You can also download the latest version of Java from https://java.com/en/download/manual.jsp. After installation of Java, if the error \(java runtime error\) pops-up while installing tool, then update the Windows and try re-installing the tool.

	![](./1079354.jpg)

1. In the last step of installation, uncheck **Show Readme** option and click **Finish** to launch the tool.

	![](./1079355.jpg)

1. The main window of eMailTrackerPro appears along with the Edition Selection pop-up. Click **OK**.

	![](./1079356.jpg)

1. The eMailTrackerPro main window appears as shown in the screenshot. To trace email headers, click **My Trace Reports** icon from View section. Here, you can see the output report of the traced email header.

	![](./1079357.jpg)

1. Click **Trace Headers** icon from **New Email Trace** section to start the trace.

	![](./1079358.jpg)

1. The pop-up window will appear, select **Trace an email I have received**. Copy the email header from the suspicious email you wish to trace and paste it in the Email headers field under **Enter** Details section.

	![](./1079359.jpg)

1. For finding email headers, open any web browser, log in to any email account and from the email inbox, open the message you'd like to view headers for. Click the **More** icon next to **Reply** icon at the top of the message pane. Select **Show original** from the drop-down list.

	>Note: In this lab, we are using a **Gmail** account to find the headers. If you are using any other email account then options will differ to view the header of the email.

	![](./1079360.jpg)

1. The header appears in a new tab as shown in the screenshot. Scroll down and **Copy** the email header, and minimize the browser window.

	![](./1079361.jpg)

1. Maximize the eMailTrackerPro window, and to paste the copied header click in the **Enter Details** text box, and then click **Trace**.

	![](./1079362.jpg)

1. The **My Trace Reports** window opens. The email location is traced in a GUI world map. The location and IP addresses may vary. You can also view the summary by selecting **Email Summary** on the right side of the window. The **Table** section right below the Map shows the entire hop in the route, with the **IP** and suspected locations for each hop.

	![](./1079363.jpg)

1. To examine the report, click **View Report** button to view the complete trace report.

	![](./1079364.jpg)

1. How do you want to open this file? the pop-up appears, choose **Google chrome** and click **OK**.

	![](./1079365.jpg)

1. The complete report appears in the chrome browser as shown in the screenshot. This concludes the demonstration of data collection by tracking email communications using eMailTrackerPro. As an analyst, you can find out the origin of suspicious emails and this tool can be used to trace the threat actors and adversaries. Using this information, the analyst can blacklist the email address and the IP addresses associated with malicious email IDs. You can document all the acquired information. This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1079366.jpg)

In this lab you have learnt how to:  

- Collect Data by Tracking Email Communications using eMailTrackerPro

---

# Exercise 5: Data Collection through DNS Interrogation

## Scenario

DNS interrogation or Whois lookup is used for finding the IP addresses for a given domain name. As an analyst, you need to retrieve DNS records of the organization&rsquo;s domain. DNS records reveal information such as DNS domain names, computer names, IP addresses, and much more about a particular network.  
  
**Lab Scenario**  
  
In the process of data collection, your next task will be to extract DNS and domain information from the organization website. You are required to perform DNS interrogation to gather useful information regarding the domains of the organization. This lab will show you how to perform DNS lookup using different DNS interrogation tools.  
  
**Lab Objectives** 

The objective of this lab is to demonstrate:  

- Gathering Organization IP and Domain Name Information using Whois Lookup
- DNS Information Gathering using nslookup

Lab Duration: **10 Minutes**

1. By default, **Windows 10** machine is selected click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the Windows 10 machine then skip to step **3**.

	![](./1079367.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If Networks prompt appears once you have logged into the machine, click **Yes**. Alternatively, navigate to **Commands** (**Thunder** icon) menu **Type Text** and click **Type Password**.

	![](./1079368.jpg)

1. Open any web browser \(here, **Mozilla Firefox**\), and type **http://whois.domaintools.com** in the address bar of the browser and press **Enter**. Whois Lookup, Domain page appears as shown in the screenshot.

	![](./1079369.jpg)

1. In the search bar, type **www.certifiedhacker.com** and click the **Search** button.

	![](./1079370.jpg)

1. This search result reveals the details associated with the URL we entered, i.e., **www.certifiedhacker.com**, which includes the organizational details like name servers, IP address, location, etc. as shown in the screenshots.  
	  
	This concludes the demonstration of gathering organization IP and domain name information using Whois Lookup. By using this tool, you can identify and gather the publicly available information related to your organization, which sometimes can pose a threat to the company. You can document all the acquired information. Close all the open windows.

	![](./1079371.jpg)

1. Now, we shall perform the **DNS information gathering** using nslookup. The next thing we will do in this lab is to look at the nslookup tool and identify the name servers for the organizational website using nslookup. Open any web browser, and navigate to **http://www.kloth.net/services/nslookup.php** website.

	![](./1079372.jpg)

1. Once the site opens, you will see the interface to lookup domain information. The first thing to do is to identify the name servers for certifiedhacker.com. In the **Domain** field, enter **certifiedhacker.com**. Click **Look it up** button and review the results that are displayed.

	![](./1079373.jpg)

1. As you can see, there is an option for IPv6, and even though as of this writing, there are very few locations that have this configured. It is good to test and make sure that it is not set up to route information. There are attacks which are possible over IPv6. But in this lab, we will test for attacks possible over IPv4. Therefore, in the Domain field, enter **cisco.com**, and in the **Query** field, click on the drop-down arrow, select **A \(IPv4 address\)** and then click **Look it up** button.  
	  
	This should result in a display similar to the one in the screenshot.

	![](./1079542.jpg)

1. Next, we will lookup the domain when given an IP address using the PTR record. Enter **8.8.8.8** in the Domain field and in the Query field, click on the drop-down arrow, select **PTR \(domain pointer\)** and then click **Look it up** button.

	![](./1079543.jpg)

1. As you can see reflected in the below screenshot, this is the **public DNS** server for **Google**. In addition, more than likely not within our scope of work in our testing unless we are contracted to test Google.  
	  
	You can also perform the same operations using nslookup command line utility. Conduct a series of queries and review the information to gain familiarity with the nslookup tool and gather information. This concludes the demonstration of DNS information gathering using nslookup. You can document all the acquired information like IP addresses, DNS server names and other DNS information.  
	  
	This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1079544.jpg)

In this exercise, you have learnt how to:  

- Gather Organization IP and Domain Name Information using Whois Lookup
- Gather DNS Information using nslookup

---

# Exercise 6: Data Collection through Automated OSINT Tools/Frameworks/Scripts

## Scenario

Automating OSINT will ease the data collection process where an analyst can gather much information with fewer efforts and in less time duration. Automated OSINT tools/frameworks/scripts use various open source web services such as Google, VirusTotal, ThreatCrowd, and so on as their sources and when a search is conducted using these automated tools, they will search for a particular query in multiple sources and provide the cumulative results respectively making the data collection process easy, simple, and effective.   
  
**Maltego**  

Maltego is one such automated OSINT tool which is effectively used by data collection experts and threat intelligence analysts in order to perform visual link analysis of the data. Maltego has in-built OSINT plugins called transforms which are effectively used for visual link analysis.   
Maltego offers products and services like Maltego Servers and Maltego Clients.   
  
**Maltego Servers**: 
  
Maltego servers can be deployed within your organization meaning that instead of having your transforms running over Paterva&rsquo;s infrastructure you can host your transform servers on infrastructure you control. An internal server gives you the ability to integrate with your structured internal data and leverage internal processes as well as the ability to distribute these transforms across your enterprise.  
  
Maltego Servers are of three types as mentioned below:  

- CTAS \(Commercial Transform Application Server\): CTAS is a server that includes all the transforms found on Paterva&rsquo;s public server. By purchasing this server, you will have your own private transform server with the benefits of using your own infrastructure to host it. This is specifically applicable to clients who do not want any of their data travelling to Paterva's infrastructure.
- iTDS \(internal Transform Distribution Server\): iTDS is Peterva&rsquo;s internal Transform Distribution Server and gives you the ability to allow custom transforms to be managed, shared and distributed from a central point within your organization. This server is suited for organizations who are building transforms that integrate with their own \(internal\) data and want to share these transforms with multiple Maltego clients on their internal network.
- Comms \(communications server\): The communications server is used to host shared graph sessions and is identical to Paterva&rsquo;s public communications server which is free to use. Purchasing your own Comms server will allow you to host shared graph sessions without the session traffic going over Paterva&rsquo;s servers.

  
**Maltego Client**:  

Maltego client is a GUI application that the end user operates to gather information and build Maltego graphs. The Maltego client makes connections to the CTAS \(Commercial Transform Application Server\) and iTDS \(internal Transform Distribution Server\) on ports 443 and 8081 to run transform.  
Maltego Clients are provided with four variants of software namely Maltego XL, Maltego Classic, Maltego CE and Casefile in which Maltego XL and Maltego Classic are the commercial variants whereas Maltego CE and Casefile are free variants.   
Maltego XL \(eXtra Large\) and Maltego Classic contain lot of additional features compared to free variants and these features include:  

- Access to commercial Transform Hub
- Use with Internal Transform servers
- Additional Max number of results per transform
- Additional Max number of entities on a graph
- Technical support

However, Maltego CE \(Commercial Edition\) is extensively helpful to all communities since it contains all basic OSINT transforms in free of cost.   
CaseFile is Paterva's offline intelligence development software. Combining Maltego's graph and link analysis functionality this tool allows for analysts to examine links between offline data. However, Casefile do not contain transforms as were in other variants. Casefile enables data security since it is an offline variant.   
Maltego is one such automated OSINT tool which is capable of collecting the following details:  

- Identify the Server-Side Technology
- Identify the Domain
- Identify the Domain Name Schema
- Identify the Service Oriented Architecture \(SOA\) Information
- Identify the Mail Exchanger
- Identify the Name Server
- Identify the IP Address
- Identify the Geographical Location
- Identify the Entities
- Find out the Email Addresses
- Find out the Phone Numbers

**Note:** In this lab, we are using Maltego CE \(Community Edition\) variant and this uses default Maltego Server. No specific internal servers have been integrated with Maltego GUI in this lab.  
  
**OSTrICa**  

OSTrICa is another automated OSINT tool where OSTrICa stands for Open Source Threat Intelligence Collector. It is an open source plugin-oriented framework to collect and visualize threat intelligence information. It is a free and open source framework that allows everyone to automatically collect and visualize any sort of threat intelligence data harvested \(IoCs\), from open, internal, and commercial sources using a plugin based architecture. Following are some of the sources for   
  
**OSTrICA**:  

- ThreatMiner
- ThreatCrowd
- BlackLists
- CymruWhois
- DomainBigData
- NortonSafeWeb
- PyWhois
- SafeBrowsing
- SpyOnWeb
- TCPIPutils
- VirusTotal
- WebSiteInformer
- WhoisXmlApi

**OSRFramework**  

OSRFramework is another automated OSINT tool which contains a set of libraries developed by i3visio to perform open-source intelligence tasks. The libraries provide a collection of scripts that can enumerate users, domains, and more across over 200 separate services.  
  
**Lab Scenario**  

In the process of data collection, as an analyst, you must be able to gather huge amounts of information about your organization by automating the data collection process, or you can use automated OSINT tools to gather such information to ease your data collection efforts. Your next task will be to extract organization related information using various automated OSINT tools. This lab will show you how to perform open-source intelligence gathering using automated OSINT tools like Maltego, OSTrICa, and OSRFramework.  
  
**Lab Objectives**  

The objective of this lab is to perform:  

- Open Source Intelligence Gathering using Maltego
- Open Source Intelligence Gathering using OSTrICa \(Open Source Threat Intelligence Collector\)
- Open Source Intelligence Gathering using OSRFramework

Lab Duration: **40 Minutes**

1. [] To launch **Parrot Security** machine, click ParrotSecurityCTIA.

    ![](./p03d2dce.jpg)

2. [] In the login page, the **Analyst** username will be selected by default. Enter password as **toor** in the **Password** field and press **Enter** to log in to the machine.

    >[!note] If a **Parrot Updater** pop-up appears at the top-right corner of **Desktop**, ignore and close it. If a **Question** pop-up window appears asking you to update the machine, click **No** to close the window.

 	![](./bd5xuiu5.jpg)

3. launch **Maltego** by navigating to **Applications** --> **Pentesting** --> **Information Gathering** --> **OSINT Analysis** --> **maltego**, as shown in the screenshot.

	![](./cbhhcswf.jpg)

4. A security pop-up appears, enter password as **toor** in the **password** field and click **OK**.

	![](./rulx4eak.jpg)

5. A **Product Selection** wizard appears on the Maltego GUI; click **Run** from **Maltego CE (Free)** option.

    >[!note] If the **Memory Settings Optimized** pop-up appears, click **Restart Now**.

	![](./3s52wnx2.jpg)

6. As the **Configure Maltego** window appears along with a **LICENSE AGREEMENT** form, check the **Accept** checkbox and click **Next**.

	![](./rerhhy2u.jpg)

7. You will be redirected to the **Login** section.

	![](./1qhkyz4w.jpg)

	>Note: If License Agreement pop-up appears, check the **Accept** and click **Next**. Login with the following Credentials: **tiaanalyst@gmail.com** **test@1234** and click **Next**. Once you have logged in with the Credentials click **Next**.  

	![](./etf10240.jpg)

8. The **Login Result** section displays your personal details; click **Next**
	
	![](./hsgiz1yl.jpg)

9. The **Install Transforms** section appears, which will install items from the chosen transform server. Leave the settings to default and click **Next**.

	![](./iyjjilny.jpg)

10. The **Help Improve Maltego** section appears. Leave the options set to default and click **Next**.

	![](./btevjr54.jpg)

11. The **Privacy Mode Options** section appears. Leave the **Privacy Mode** set to default and click **Next**.

	![](./0wyxaf2v.jpg)

12. The **Ready** section appears. Leave the selection to default and click **Finish**.

	![](./rwb4tatp.jpg)

13. The **New Graph (1)** window appears, as shown in the screenshot.

	![](./p2ve3k00.jpg)

14. In the left-pane of **Maltego GUI**, you can find the **Entity Palette** box, which contains a list of default built-in transforms. In the **Infrastructure** node under **Entity Palette**, observe a list of entities such as **AS**, **DNS Name**, **Domain**, **IPv4 Address**, **URL**, **Website**, etc.

15. Drag the **Website** entity onto the **New Graph (1)** window.

16. The entity appears on the new graph, with the **www.paterva.com** URL selected by default.

    >[!note] If you are not able to view the entity as shown in the screenshot, click in **the New Graph (1)** window and **scroll up**, which will increase the size of the entity.

	![](./u0ksdxqn.jpg)

17. Double-click on **www.paterva.com** and rename the domain name to **www.certifiedhacker.com** and press **Enter**.

	![](./4f2pffls.jpg)

18. After adding the domain entity, we shall now identify the server-side technology. **Right-click** the entity and select **All Transforms**.

	![](./kdj5u1de.jpg)

19. The Run Transform\(s\) list appears. Click **To Server Technologies \[Using BuiltWith\]**.

	![](./ek3vpu4i.jpg)

20. Maltego starts running the transform **To Server Technologies \[Using BuiltWith\]** entity. Once Maltego completes the Transforming Server-Side Technologies, it displays the technology implemented on the server that hosts the website, as shown in the screenshot.  
	  
	After obtaining the built-in technologies of the organizational server, as an analyst, you can search for vulnerabilities related to any of them and simulate exploitation techniques to identify any presence of threats.

	>Note: If an error appears, click on dot icon to close it and then right click again on the website entity and click To Server Technologies \[Using BuiltWith\] entity. It starts running without any error.

	![](./x2lnknhg.jpg)

21. To start a new transform, select all the entities by pressing **Ctrl\+A** on the keyboard and press **Delete**. A Delete pop-up appears, click **Yes**.

	![](./xhjotj0g.jpg)

22. Follow steps **15**, **16** &amp; **17** to create a website entity with the URL **www.certifiedhacker.com**. After adding the domain entity, we shall now **identify the domain**.

	![](./lllxtltc.jpg)

23. Right-click the entity and select **All Transforms** and click **To Domains \[DNS\]**.

	>Note: If an error appears, click on dot icon to close it and then **right click** again on the website entity and click To Domains \[DNS\] entity. It starts running without any error.

	![](./x3gjs1t3.jpg)

24. The **domain corresponding** to the website displays, as shown in the screenshot.

	![](./vj5ymhka.jpg)

25. After adding the domain entity, we shall now identify the domain name schema. **Right-click** on any of the corresponding domain \(here, **certifiedhacker.com**\) and select **All Transforms** and click **To DNS Name \[Using Name Schema diction&hellip;\]**.

	![](./tq0qnawz.jpg)

26. This transform will attempt to test various name schemas against a domain and try to identify a specific name schema for the domain as shown in the screenshot. After identifying the name schema of the organizational domains, as an analyst, you can attempt to simulate various exploitation techniques to gain sensitive information related to the resultant name schemas. For example, you can implement a brute force or dictionary attack to log in to ftp.certifiedhacker.com and gain confidential information.  
	  
	Select only the **name schemas** by holding and dragging mouse pointer and **delete** them. Click **Yes** if Delete pop-up appears.

	![](./ty1fjecc.jpg)

	![](./nxxyt4tn.jpg)

27. Now, we shall identify the Service Oriented Architecture \(SOA\) information. **Right-click** the entity \(here, **certifiedhacker.com**\) and select **All Transforms** and click **To DNS Name &ndash; SOA \(Start of Authority\)**.

	![](./b4iu2102.jpg)

28. This returns the **primary name server** and the **email of the domain administrator**, as shown in the screenshot. By extracting the SOA related information, you can attempt to find vulnerabilities in the services and architectures and attempt to exploit them.  
	  
	Select both the name server and the email by holding and dragging the mouse pointer and **delete** them. Click **Yes** if Delete pop-up appears.

	![](./dwhptoxt.jpg)

29. Now, we shall **identify the mail exchanger** information. **Right-click** the corresponding domain entity \(here, **www.certifiedhacker.com**\) and select **All Transforms** and click **To DNS Name - MX \(mail server\)**.

	![](./50kh1iqa.jpg)

30. This transform returns the mail server associated with the **www.certifiedhacker.com** domain as shown in the screenshot.  
	  
	By identifying the mail exchanger server, you can attempt to exploit the vulnerabilities in the server. If the server is vulnerable and gets exploited, this can allow performing malicious activities such as sending spam e-mails. Select **mail exchanger server** and **delete**. Click **Yes** if Delete pop-up appears.

	![](./gcs0ci11.jpg)

31. Now, we shall **identify the Name Server** information. **Right-click** the corresponding domain entity \(here, **www.certifiedhacker.com**\) and select **All Transforms** and click **To DNS Name - NS \(name server\)**.

	![](./rlex0zks.jpg)

32. This returns the name servers associated with the domain. By identifying the primary name server, you can implement various techniques to attempt to exploit the server and thereby perform malicious activities by disguising yourself as an attacker such as DNS Hijacking, and URL redirection.  
	  
	Select both the name servers and domain entity by holding and dragging the mouse pointer and **delete** them. Click **Yes** if Delete pop-up appears.

	![](./xczzzbj1.jpg)

33. Now, we shall identify the IP address information. **Right-click** the main entity and select **All Transforms** and click **To IP Address \[DNS\]**.

	![](./ainboisq.jpg)

34. This displays the IP address of the website. By obtaining the IP address of the website, you can simulate various scanning techniques to find open ports and vulnerabilities, and thereby attempt to intrude in the network and attempt to exploit them.

	![](./t0t0kdqc.jpg)

35. Now, we shall identify the Geographical Location information. **Right-click** the IP address entity and select **All Transforms** and click **To Location \[city, country\]**.

	![](./jw3d5xd1.jpg)

36. This transform identifies the geographical location where the IP address is located, as shown in the screenshot. By obtaining the information related to geographical location, you can attempt social engineering attacks by making voice calls \(vishing\) to an individual in an attempt to leverage sensitive information.

	![](./rtmvyyvh.jpg)

37. Now repeat the steps **23** and **24**, to extract Domain entities.

	![](./zqnyjt23.jpg)

38. **Right-click** the domain entity (**certifiedhacker.com**) and select **All Transforms** and click **To Entities from WHOIS \[IBM Watson\]**.

	![](./wweyiunq.jpg)

39. This transform returns the entities pertaining to the owner of the domain, as shown in the screenshot. By obtaining this information, you can attempt to exploit the servers displayed in the result or simulate a brute force attack or any other technique to identify the possibility of to hack into the admin mail account and send phishing emails to the contacts in that account.

	![](./ajxw4wk0.jpg)
	  
40. Apart from the transforms mentioned above, there are also transforms that can identify the phone numbers, track accounts, and conversations of individuals who are registered in social networking sites such as Facebook and Twitter. As an analyst, it is your responsibility to employ various techniques to identify the vulnerabilities present inside the organization and that can pose threats to the organization. In this process, with the appropriate legal permission, you can also attempt to simulate actions such as enumeration, targeted attacks, web application hacking, social engineering, etc. in order to gather threat information which may allow access to a system or network, gain credentials, etc.  
	  
	This concludes the demonstration of open source intelligence gathering using Maltego. You can document all the acquired information. **Close** all the open Windows.
	
41. Now, we shall perform the open source intelligence gathering using **OSTrICa** \(Open Source Threat Intelligence Collector\). Click the **MATE Terminal** icon at the top-left corner of the **Desktop** window to open a **Terminal** window. In the Terminal window type **ls** and press **Enter**.

	![](./4csx3gm4.jpg)

42. Now, change the directory to **OSTrICa**. Type **cd OSTrICa** and press **Enter**.

	![](./icnesjz1.jpg)

43. Now to launch OSTrICa tool, type **python main.py** and press **Enter**. Since OSTrICa is developed in python language. Executing the above command will load all the required plugins of open source data collection tools.

	![](./qgzuxx0y.jpg)

44. To add the domain to OSTrICa, type **domain=www.certifiedhacker.com** and press **Enter** in the OSTrICa console as shown in the screenshot.

	![](./gyex0250.jpg)

45. To perform open source intelligence, type **run** and press **Enter** in the console.

	>Note: This extraction may take a couple of minutes to complete.

	![](./lhc4gxfe.jpg)

46. After the completion of the intelligence extraction, now, type **graph** and press **Enter** to generate a graph corresponding to the gathered intelligence. This graph will be in the **.html** format and will be generated in **/root/OSTrICa/viz** folder by default with a random name.  
	  
	Minimize the terminal window.

	![](./gwcaclcq.jpg)

47. Navigate to **/Analyst/OSTrICa/viz** folder and right click the **&lt;random name&gt;.html** file select open with **Firefox** 

	![](./qmqzr4wc.jpg)

48. The report will open in the **Mozilla Firefox** browser. The extracted intelligence will appear as shown in the screenshot. In the web page, at the left-bottom corner, you can observe all the available plugins from which OSTrICa has extracted the intelligence.

	>Note: You can zoom in and out for clear visualization of the extracted intelligence and interconnection between the nodes.

	![](./34gehblc.jpg)

49. The nodes or dots are represented in different colours with respect to the different, available plugins. The interconnections between the nodes represent the relation between the nodes whether it is **IP** or **associated domain**, etc.  
	  
	Now to identify the intelligence extracted specifically related to the **www.certifiedhacker.com** domain, in the **Search** bar that is present in the bottom-right corner, type **www.certifiedhacker.com** and press **Enter**. The result of the search is shown in the screenshot.  
	  
	We can identify that the www.certifiedhacker.com domain is associated with IP&rsquo;s 69.89.31.193, 183.82.41.50, 202.75.54.101, 162.241.216.11, and 64.90.163.30.  
	  
	In this task, we have used the domain as a parameter to extract the intelligence, however, by exploring the help available in OSTrICa tool, the analyst can also extract required open source intelligence by using various other parameters. This concludes the demonstration of open source intelligence gathering using OSTrICa \(Open Source Threat Intelligence Collector\). You can document all the acquired information. Close all the windows.

	![](./lknyt03e.jpg)

50. Click the **MATE Terminal** icon at the top-left corner of the **Desktop** window to open a **Terminal** window. 

51. A **Parrot Terminal** window appears. In the terminal window, type **sudo su** and press **Enter** to run the programs as a root user.

52. In the **[sudo] password for Analyst** field, type **toor** as a password and press **Enter**.

    >[!note] The password that you type will not be visible.

	![](./qfwvron3.jpg)

53. Now type **usufy.py -n &lt;target username or profile name&gt; -p twitter youtube** and press **Enter**. In this lab, the target username is the **analyst**.

	>Note: Here, **-n** denotes the list of nicknames to process and **-p** denotes platform for search. **usufy.py** checks for the existence of a profile for given user details in the different platforms

	![](./kjlbonzi.jpg)

54. The **usufy.py** will search the user details in the mentioned platform and will provide you with the existence of the user by searching through multiple social networking sources and feeds as shown in the screenshot.

	>Note: The Search may take **5** to **10** minutes of time according to social networking sites that you have provided to search.

	![](./5dub0gd1.jpg)

55. Click the **MATE Terminal** icon at the top-left corner of the **Desktop** window to open a **Terminal** window. 

56. A **Parrot Terminal** window appears. In the terminal window, type **sudo su** and press **Enter** to run the programs as a root user.

57. In the **[sudo] password for Analyst** field, type **toor** as a password and press **Enter**.

    >[!note] The password that you type will not be visible.

	![](./0g135fzg.jpg)

58. Now type **searchfy.py &ndash;q &lt;Page Name or Handler Name&gt;** and press **Enter**. (**Searchfy.py** checks with the existing users of a pages/handlers for given details in all the social networking platforms\). In this lab, we are providing **certifiedhacker**.

	>Note: If **searchfy.py** is taking more 2 minutes you can press **Ctrl\+C** to view the gathered information.

	![](./tovt0fo0.jpg)

59. It will obtain all the user details who are subscribed to targeted social networking pages that are provided, as shown in the screenshot.  
	  
	This concludes the demonstration of open source intelligence gathering using **OSRFramework**. You can document all the acquired information like domains, IP addresses, usernames, and other information present on the social networking websites. This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./5bgcki3o.jpg)

In this exercise, you have learnt how to perform:  

- Open Source Intelligence Gathering using Maltego
- Open Source Intelligence Gathering using OSTrICa \(Open Source Threat Intelligence Collector\)
- Open Source Intelligence Gathering using OSRFramework

---

# Exercise 7: Data Collection through Social Engineering Techniques

## Scenario

Social engineering is the art of convincing people to reveal confidential information. Social engineers depend on the fact that people know certain valuable information yet are generally careless in protecting it. The Social Engineering Toolkit and SpeedPhish Framework \(SPF\) are open-source python-driven tools specifically designed to perform advanced attacks against human \(employees\) by exploiting human behaviour. These tools are used to target key persons in the organization during acquiring threat intelligence.  
  
**Lab Scenario**  

Social engineering is the art of convincing people to reveal sensitive information in order to perform some malicious action. Organizations fall victim to social engineering tricks despite having security policies and best security solutions in place, as social engineering targets people&rsquo;s weaknesses or good nature. Reconnaissance and social engineering is generally an essential component of any information security attack. Cybercriminals are increasingly utilizing social engineering techniques to exploit the most vulnerable link in information system security i.e., employees. Social engineering can take many forms, including phishing emails, fake sites, and impersonation.   
It is essential for you, as an analyst to assess the preparedness of your organization or the target of evaluation against the social engineering attacks. In this lab, the analyst performs a phishing attack within the organization to assess the awareness of the employees on phishing tricks and techniques. Though social engineering primarily requires soft skills, this exercise demonstrates some techniques that facilitate or automate certain facets of social engineering attacks and collect internal threat information.  
  
**Lab Objectives**  

The objective of this lab is to demonstrate:  

- Phishing Employee Credentials using Social-Engineer Toolkit \(SET\)
- Phishing Employee Credentials using SpeedPhish Framework \(SPF\)

Lab Duration: **30 Minutes**  

1. To launch **Parrot Security** machine, click ParrotSecurityCTIA.

    ![](./p03d2dce.jpg)

	>Note: If you are already logged skip to step **3**.

2. In the login page, the **Analyst** username will be selected by default. Enter password as **toor** in the **Password** field and press **Enter** to log in to the machine.

    >[!note] If a **Parrot Updater** pop-up appears at the top-right corner of **Desktop**, ignore and close it. If a **Question** pop-up window appears asking you to update the machine, click **No** to close the window.

 	![](./bd5xuiu5.jpg)
	
3. Click the **MATE Terminal** icon at the top of the **Desktop** window to open a **Terminal** window.

4. A **Parrot Terminal** window appears. In the terminal window, type **sudo su** and press **Enter** to run the programs as a root user.

5. In the **[sudo] password for Analyst** field, type **toor** as a password and press **Enter**.

    >[!note] The password that you type will not be visible.

	![](./p5l4alo2.jpg)

6. Now, type **cd** and press **Enter** to jump to the root directory.

	![](./utbacyta.jpg)

7. Type **setoolkit** and press **Enter** to navigate to the setoolkit folder.

	![](./hnjwluor.jpg)

8. Type **y** and press **Enter** to agree to the terms of services

	>Note: If you are launching set-toolkit for the first time, you may be asked whether to enable bleeding-edge repos. Type no and press **Enter**.

	![](./omf3xtwi.jpg)

9. You will be presented with the **SET** menu, type **1** and press **Enter** to choose **Social-Engineering Attacks**

	![](./rvox22lc.jpg)

10. A list of menus in **Social-Engineering Attacks** will appear; type **2** and press **Enter** to choose **Website Attack Vectors**.

	![](./gkwxqbta.jpg)

11. In the next menu that appears, type **3** and press **Enter** to choose **Credential Harvester Attack Method**.

	![](./kzf5albg.jpg)

12. Now, type **2** and press **Enter** to choose **Site Cloner** from the menu.

	![](./y3xqpnng.jpg)

13. Type the IP address of your Parrot Security machine in the prompt for &ldquo;**IP address for the POST back in Harvester/Tabnabbing,**&rdquo; and press **Enter**. \(Here, the IP address of Parrot Security machine is **10.10.1.11**\)

	![](./wy3xqllw.jpg)

14. Now, you will be prompted for a URL to be cloned; type the desired URL for &ldquo;**Enter the** **url** **to clone**&rdquo; and press **Enter**. In this example, we have used **http://certifiedhacker.com/Online%20Booking/index.htm**. This will initiate the cloning of the specified website. 

	![](./kvomobyr.jpg)

15. After cloning is completed, a message will appear on the Terminal screen of SET as shown in the screenshot. It will start **Credential Harvester**.

	![](./tl3prvwr.jpg)

16. Now, open a Mozilla Firefox browser, and log into your **working email account**.

17. Now, you must send the **Cloned Website** to the victim and trick him/her to click the malicious link. Click **Compose** button to write an email, and provide victim's email ID \(you can use your own another email account for demonstration purpose\) and provide the Subject, and then type in the text which will lure the victim to click the malicious link \(Cloned Website\).  
	  
	Then click **Insert link** icon as shown in the screenshot.  
	  
	 ![](./rn2.jpg)
	
18. Edit Link window appears, type **http://www.hotelbooking.com/holiday_offers** in the **Text to display** field. Make sure that Web address radio button is selected under Link to section and type **http://10.10.1.11** in the respective field, and then click **OK**.

	>Note: 10.10.1.11 is the IP address of the Parrot Security machine.

	![](./rn3.jpg)

19. The fake URL should appear in the message body. To verify that the fake URL is linked to the real one, click the fake URL; it will display the actual URL as &ldquo;**Go to link**:&rdquo; followed by the actual URL. **Send** the email to the intended victim.

	![](./rn4.jpg)

20. Click Windows10 and click **Ctrl+Alt+Delete**.

21. Type **Pa$$w0rd** in the Password field and press **Enter**.

	>Note: If Networks pop-up appears, click **Yes**.

22. Launch any browser, and log into the Victims email account, and click the **email received** from the attacker.

23. Now, click the **Malicious** link.

	![](./rn5.jpg)

24. The victim will be prompted to enter his/her username and password into the form fields \(present at the bottom of the web page\), is that this appears to be a genuine website. When the victim enters the **EMAIL** and **PASSWORD** and clicks **Sign in**, it does not allow logging in; instead, it shows an error page or it redirects him/her to the legitimate hotelbooking login page. Observe the URL in the browser.  
	  
	For demonstration purpose, you can enter any random text in the **Email** and **Password** fields and click **Sign in**.  
	  
	**Close** the browser window.

	![](./rn6.jpg)

25. As soon as the victim types in the email address and password and clicks Sign in, switch to Parrot Security machine, click ParrotSecurityCTIA, the SET in Parrot Security machine fetches the typed **EMAIL** and **PASSWORD**, which can then be used to gain **unauthorized access** to the victim&rsquo;s account.  
	  
	The email and password that are captured in the Parrot Security machine are displayed as shown in the screenshot. This concludes the demonstration of phishing employee credentials using Social-Engineer Toolkit \(SET\). If you are successful in performing such attacks, the victim present in the organization is obviously not aware of the phishing attacks and this can pose a serious threat to the organization. As an analyst, you must collect such information to build threat intelligence. You can document all the acquired information.  
	  
	Close setoolkit terminal window and minimize the browser window.

	>Note: Do not close the logged in email account in the browser. Minimize the browser window. 

	![](./jpm5lmvy.jpg)

26. Now, we shall perform phishing employee credentials using **SpeedPhish Framework \(SPF\)**. Click the **MATE Terminal** icon at the top of the **Desktop** window to open a **Terminal** window.

27. In the terminal window type **cd SPF** and press **Enter**.

	![](./v1xnbotr.jpg)

28. Now, type **cd spf** and press **Enter**.

	![](./jocgq2tp.jpg)

29. **To view SPF help commands, type **./spf.py -h** and press **Enter**. Help page of SPF appears as shown in the screenshot.**

	![](./1079616.jpg)

30. To check the configuration of **SPF**, type **cat default.cfg** and press **Enter**. The configuration details appear as shown in the screenshot.

	![](./1079617.jpg)

31. In the terminal window, type **./spf.py -d example.com --test** and press **Enter** to run SPF. SPF starts by showing you the **TEMPLATE LIST** first, and then it proceeds to Start phishing web server as shown in the screenshot.

	![](./1079618.jpg)

32. SPF then proceeds to **Starting SMB Server**, then it starts Obtaining the list of email targets and **EMAIL LIST** and displays them. Then SPF starts Locating phishing email templates and starts Sending phishing emails one by one as shown in the screenshot.

	![](./1079619.jpg)

33. After SPF finishes sending phishing emails, it starts **Monitoring Services** as shown in the screenshot.

	![](./1079620.jpg)

34. Scroll up to locate website address of **Office 365** and note down the website address as shown in the screenshot.

	![](./1079659.jpg)

35. Also, locate and note down the location of the **email template** for **Office 365** as shown in the screenshot.

	![](./1079661.jpg)

36. Now navigate to the location of the **phishing email template** located at **/Home/SPF/spf/templates/email** and open **office365.txt**. The file opens giving you a template, which you will use to send a phishing email to the victim. Use the content of this template to compose a phishing email.

	![](./1079663.jpg)

37. Masquerading as an **IT Support** professional, you write an email to the victim present in the organization with the purpose of making him/her click on the phishing link obtained in Step **31**.  
	  
	Open a browser and log in with your email ID and compose an email as shown in the screenshot. After composing the email, place the cursor where you wish to place the fake URL. Then, click the **Insert link** icon.

	>Note: In this lab we are using two **Gmail** accounts for the demonstration purpose. If you are using other email clients then screenshots will differ. In the To field type victims email ID. You can use another email account if you have.

	![](./1079665.png)

38. The **Edit Link** window appears. In the Text to display field type the text that you want to display \(here, **Office 365 Link**\), and in the Web address field type the malicious URL link that you have obtained at step 31 i.e., **http://192.168.1.11:8005** and click **OK**.

	![](./1079668.jpg)

39. The URL has been linked to **Office 365 Link** text as shown in the screenshot. Now send the e-mail to the victim in the organization.
 
	![](./1079669.jpg)

40. Assume yourself as the victim. Now from the **Resources** pane click **Windows 10** machine, if the machine is locked login with the credentials. Open any browser \(here, **Mozilla Firefox**\), log in with the email account that you sent an email. In the Inbox click the new email that you have received, and click the **Malicious link**.

	![](./1079670.jpg)

41. When the victim clicks the link, he/she is redirected to a webpage which looks exactly like the **Office 365** login page, but by taking a closer look at the URL anyone can notice that it is the malicious phishing link. An unsuspecting user may not be aware of this and will continue with the malicious webpage and enters his/her user credentials and click **Sign In**.

	![](./1079671.jpg)

42. You may be redirected to the Google home page or to the Error page.

	![](./1079672.jpg)

43. Switch to **Parrot Security** machine, and switch to **SPF** terminal window, you will see that SPF has obtained the victim&rsquo;s credentials as shown in the screenshot.

	>Note: If the machine is locked, log in with the credentials.

	![](./1079673.jpg)

44. Press **Ctrl\+C** to stop SPF and generate a report. SPF exits and displays the location of the report file as shown in the screenshot.  
	  
	This concludes the demonstration of phishing employee credentials using SpeedPhish Framework \(SPF\). The victim present in the organization is not aware of the phishing attacks and this can pose a threat to the organization. As an analyst, you must collect such information to build threat intelligence. You can document all the acquired information. This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1079675.jpg)

In this exercise, you have learnt how to perform:  

- Phishing Employee Credentials using Social-Engineer Toolkit \(SET\)
- Phishing Employee Credentials using SpeedPhish Framework \(SPF\)

---

# Exercise 8: Data Collection through Malware Analysis

## Scenario

Malware analysis is a process of reverse engineering a specific piece of malware to determine the origin, functionality, and potential impact of a given type of malware. By performing malware analysis, the detailed information regarding the malware can be extracted. Many tools and techniques exist to perform such tasks. Malware analysis is an integral part of any threat intelligence data collection process.  
Some of the primary objectives of analyzing a malware include:  

- Determine what happened exactly
- Determine the malicious intent of malware software
- Identify indicators of compromise
- Determine the complexity level of an intruder
- Identify the exploited vulnerability
- Identify the extent of damage caused by intrusion
- Catch the perpetrator accountable for installing the malware
- Find signatures for host and network-based intrusion detection systems
- Evaluate harm from an intrusion
- List the indicators of compromise for different machines and different malware programs
- Find the system vulnerability malware has exploited
- Distinguish the gatecrasher or insider responsible for the malware entry
  
**Lab Scenario**  

Attackers these days are using sophisticated malware techniques as cyber weapons to steal sensitive data. Malware such as viruses, Trojans, worms, spyware, and rootkits allow an attacker to breach security defences and subsequently launch attacks on target systems. The malware can inflict intellectual and financial losses to the target, whether it be an individual, a group of people or an organization. The worst part is that it spreads from one system to another with ease and stealth. Thus, it is the responsibility of an analyst to find and cure the existing infections and thwart future. This can be achieved by performing malware analysis. This lab will show you how to perform malware analysis using various open-source malware analysis tools like VirusTotal, Blueliv Threat Exchange Network and Valkyrie.  
  
**Lab Objectives**  

The objective of this lab is to demonstrate:  

- Analyzing Malware using VirusTotal and Maltego
- Analyzing Malware using Blueliv Threat Exchange Network
- Analyzing Malware using Valkyrie

Lab Duration: **45 Minutes**

1. Click Windows10 and click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the **Windows 10** machine then skip to step **3**.

	![](./1079685.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If **Networks** prompt appears once you have logged into the machine, click **Yes**. Alternatively, navigate to **Commands** (**Thunder** icon) menu **Type Text** and click **Type Password**.

	![](./1079686.jpg)

1. Open any web browser (here, **Mozilla Firefox**\). Mozilla Firefox browser appears, in the address bar type **https://www.virustotal.com/home/upload** and press **Enter**. VirusTotal home page appears, click **Choose file** button as shown in the screenshot.

	![](./1079771.jpg)

1. **File Upload** window appears. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Malware\\wiki**, select the **wikiworm.exe** application and click the **Open** button.

	![](./1079772.jpg)

1. **VirusTotal** will automatically start computing the hashes and other signatures with the well-known threat indicators from various sources and produce a malware infection score. The result of the malware analysis of **wikiworm.exe** is shown in the screenshot.  
	  
	You can see the VirusTotal score as **57**/**68**. You can also see various details about the malware like SHA-256, File name, File size, Last analysis, and Community score. You can also see all the results in detail under **Detection** tab.

	![](./1079773.jpg)

1. Click on **Details** tab to extract more details or IoC&rsquo;s of the malware like MD5, SHA-1, Authentihash, Imphash, SSDeep, TRiD, Tags, File Names, etc.  
	  
	Document all these details, we shall be using these details of indicators of compromise \(IoCs\) in the upcoming labs.

	![](./1079774.jpg)

1. Click **Relations** tab to view the relations of the malware using Graph Summary along with the Compressed Parents details.

	![](./1079775.jpg)

1. Click **Community** tab to view the number of votes voted by the community members under the Votes section. You can also view the Voting Details and Comments of the community members over the malware.

	![](./1079776.jpg)

1. Click on the **Details** tab and leave the window open. We shall be using the details in further steps. Minimize the browser.

	![](./1079777.jpg)

1. To install Maltego, navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Maltego** and double-click **maltego\_JRE64.v4.1.6.11045.exe** to install Maltego.  
	  
	This tool requires **Java runtime**, so if any pop-up window related to java installation appears, continue with the installation of java by clicking **OK**. Once the Java installation is completed, Maltego will start installing.  
	  
	Follow the wizard-driven installation steps to install **Maltego**.

	>Note: If the User Account Control pop-up appears, click **Yes**.

	![](./1079778.jpg)

1. After the installation is complete, check the **Create Desktop Shortcut** check-box and click the **Finish** button to complete the installation of Maltego.

	![](./1079779.jpg)

1. Double-click on the **Maltego** shortcut present on the **Desktop** to launch the Maltego tool.

	![](./1079780.jpg)

1. A Product Selection wizard appears on the Maltego GUI. Click **Run from Maltego CE \(Free\)** option.

	![](./1079781.jpg)

1. You will be redirected to the Login section. Enter the **Email Address** and **Password** specified at the time of registration, solve the captcha, and click **Next**.

	![](./1079782.jpg)

1. The Login Result section displays your personal details. Click **Next**.

	![](./1079783.jpg)

1. The Install Transforms section appears, click **Next**.

	![](./1079784.jpg)

1. Help Improve Maltego window appears, click **Next**.

	![](./1079785.jpg)

1. In the Ready window, check the **Go away, I have done this before!** radio button and click **Finish**.

	![](./1079786.jpg)

1. The Maltego GUI appears. Now, we need to install **VirusTotal transform** in Maltego. To install, in the **Transform Hub** box present at the right-pane, scroll down till you locate **VirusTotal Public API** and click **Install** button.

	>Note: If an updates pop-up window appears at the right-bottom of the window, either install the updates or you can continue with the lab steps. If you choose to update, it will download the updates and restart the Maltego application.

	![](./1079787.png)

1. Install Transforms pop-up window appears. Click **Yes**.

	![](./1079788.jpg)

1. **VirusTotal Public API** window appears as shown in the screenshot.

	![](./1079789.jpg)

1. Now, we need a **VT Public API Key** in order to proceed further. This key can be found in the **VirusTotal** website. You need to register in VirusTotal community. Maximise the **Mozilla Firefox** and open a new tab. In the address bar of the new tab type **https://www.virustotal.com/join-us** and press **Enter**, fill the details and click **Join us** button to join the community.

	![](./1079790.jpg)

1. **Signed up successfully** pop-up appears, close the pop-up window.

	![](./1079791.jpg)

1. Now, **VirusTotal** has sent you an **activation email**. Open a new tab and access your **email** that was provided at the time of registration. Once you have logged into the email account, click the email that you have received from the **VirusTotal**. Click the **Activation Link** to activate your VirusTotal account.

	![](./1079794.jpg)

1. **Account Activated** message appears, as shown in the screenshot close the pop-up window.

	![](./1079795.jpg)

1. VirusTotal home page appears, click **Sign in** at the top right corner of the browser. After the successful registration and activation, login to the VirusTotal community with the credentials that you have provided during registration.

	![](./1079792.jpg)

1. Sign in window appears, log in to the **VirusTotal** community with the credentials that you have provided at the time of registration and click **Sign In**.

	![](./1079793.jpg)

1. After logging in, click on the **User** icon present at the top-right corner of the window and click **Settings** as shown in the screenshot.

	![](./1079796.jpg)

1. Click **API Key** in under the **Public Profile** section. **Copy** the **API Key** content and sign out from the VirusTotal and email and close all the new tabs except the first one and minimize the browser window.

	![](./1079797.jpg)

1. Switch back to Maltego tool and in VT Public API Key field, **paste the copied key** and click **OK**.

	![](./1079798.jpg)

1. The Install **VirusTotal Public API** window appears and the API will be installed. After the installation is completed, click on the **Finish** button.

	![](./1079799.jpg)

1. Click **Create a new graph** icon from the top left corner of the Maltego window as shown in the screenshot.

	![](./1079800.png)

1. New Graph \(1\) tab appears, in the Maltego dashboard. Close the **Run View** section from the left pane. In the left pane search for Malware and drag and drop the **Hash entity** to the **new graph \(1\)**.

	![](./1079801.jpg)

1. Switch to the web browser that contains VirusTotal scan result - **Details** tab for **wikiworm.exe** that we have left open. Copy the **MD5 hash** content from the **Basic Properties** section. Minimize the browser window.

	![](./1079802.jpg)

1. Switch back to the **Maltego** and double-click on the hash entity&rsquo;s default hash value to rename. Paste the **MD5 hash value** of the **wikiworm.exe** file as shown in the screenshot.

	![](./1079803.jpg)

1. **Right-click** on the hash entity and in the **Run Transform\(s\)** context menu, click **\[VTPUB\] Check Hash Report** option.

	![](./1079804.jpg)

1. The **Required inputs** pop-up window appears. Click **Run!**

	![](./1079805.jpg)

1. This transform will be executed and you can see the status of the process in the Running Transforms process bar at the bottom of the window. After the process is completed, it **extracts all the information** associated with the **malware** **hash value**.

	>Note: You can click Zoom out icon to view the complete analysis of the malware by clicking on Zoom out button from the menu bar.

	![](./1079806.jpg)

1. To delete the Run Transform\(s\) result, select only the obtained results leaving the **hash entity** by holding and dragging the mouse pointer over the result and **delete** them. Click **Yes** if Delete pop-up appears.

	![](./1079807.jpg)

1. Right-click on the hash entity and in the **Run Transform\(s\)** context menu, click **vtprivCheckHash** option.

	![](./1079808.jpg)

1. The **Required** **inputs** pop-up window appears. Click **Run!**

	![](./1079809.jpg)

1. This transform will be executed and you can see the status of the process in the **Running Transforms** process bar at the bottom of the window. After the process is completed, it **extracts all the information** associated with the **malware hash value**.  
	  
	Here, we have analyzed the **wikiworm.exe** malware using VirusTotal online intelligence gathering tool and reverse engineered the malware by installing **VirusTotal API in Maltego**.  
	  
	Maltego is an intelligence gathering tool with vast applications and features. You can install other threat intelligence based API&rsquo;s as mentioned below \(not limited to\), depending on your requirement. The more you install, the better will be the acquired intelligence.  
	
	- Cisco Threat Grid
	- Kaspersky Lab
	- ZETAlytics Massive Passive
	- ThreatMiner
	- PassiveTotal
	- ThreatConnect
	- Recorded Future
	- ThreatGrid
	- Palo Alto Networks AutoFocus
	- FlashPoint
	- CrowdStrike
	- FireEye iSIGHT Intelligence
	- Domain Tools
	- ThreatCrowd
	
	This concludes the demonstration of analyzing malware using VirusTotal and Maltego. You can document all the acquired information. Close all the open Windows.  
	  
	>Note: While closing Maltego window, Save pop-up appears, click **Discard all** button.

	![](./1079810.jpg)

1. Now, we shall perform analyzing malware using **Blueliv Threat Exchange Network**. Open any web browser \(here, **Mozilla Firefox**\). In the address bar of the browser type **https://community.blueliv.com/\# !/u/signup** and press **Enter**. The sign-up form appears, fill the required details in the sign-up form and click **CREATE ACCOUNT** button to create an account.

	>Note: Please provide working email ID at the time of registration. Once the registration is done, you will receive an activation email. Activate your account as instructed in the email in order to use the tool. This site will use cookies pop-up appears, click **Accept**.

	![](./1079811.jpg)

1. **WELCOME!** the pop-up appears, stating that you need to confirm the account for activation. Open the email account in a new tab of the browser that you have provided at the time of registration.

	![](./1079812.jpg)

1. Once you have logged into the email account, click the email that you have received from the **Blueliv THREAT EXCHANGE NETWORK**, and click the activation link to validate.

	![](./1079813.jpg)

1. Confirmation of the Account Activation page appears, as shown in the screenshot. Click the link **Click here to log in**.

	![](./1079814.jpg)

1. **LOG IN** screen appears, provide the registered email ID in the **Username** field and provide the password in the **Password** field and click **LOG IN**.

	![](./1079815.jpg)

1. The Welcome page appears. To analyze a malware using Blueliv sandbox, click on the **SANDBOX** option in the menu bar at the top-right corner of the webpage.

	![](./1079816.jpg)

1. The SANDBOX page appears in the middle-pane of the window, click on **BROWSE&hellip;** button.

	![](./1079817.jpg)

1. File Upload window appears, navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Malware\\wiki** folder and select the **wikiworm.exe** malware file and click the **Open** button.

	![](./1079818.jpg)

1. After the upload is successful, click **ADD** button.

	![](./1079819.jpg)

1. The malware will be analyzed, and after the analysis, the result will be displayed at the bottom of the web page. The result generally indicates whether the malware analysis status is Queued, Discarded, Analyzing, Finished Erroneously, or Finished Successfully depending on the status of the process under the Analysis status column of the table. The severity of the malware will be indicated in three colours specifically yellow, orange, and red depending on the severity of the analyzed malware, under the Severity column.  
	  
	Click on the Name of the result to gather the details regarding the analyzed malware.

	![](./1079820.jpg)

1. The **SUMMARY** page opens up and you can gather the details like MD5, SHA1, SHA256, SSDeep, connections, signatures, DNS resolutions, HTTP requests, etc. from this result. This information can be used by the analyst to create custom IoCs for threat detection in real-time environments. You can also view the VirusTotal detection ratio beside the **SUMMARY** tab.

	![](./1079821.jpg)

1. Click on the **DETAIL** tab as shown in the screenshot. By default, the Static tab will be selected and the results related to the static malware analysis will be displayed. These details include the packer and size info, SSDeep, YARA, Language, the section, DLL&rsquo;s, API Calls, etc.

	![](./1079822.jpg)

1. Click the **Dynamic** tab to view and gather the dynamic malware analysis results such as processes created, dropper files, etc.

	![](./1079823.jpg)

1. Click the **Network** tab to view and gather the network related details exhibited by the malware such as DNS protocols, HTTP requests and responses, etc.  
	  
	This concludes the demonstration of analyzing malware using Blueliv Threat Exchange Network. You can document all the acquired information. Logout from all the accounts that you have logged in and close all the open Windows.

	![](./1079824.jpg)

1. Now, we shall perform analyzing malware using **Valkyrie**. Open any web browser \(here, **Google Chrome**\). In the address bar of the browser type **https://valkyrie.comodo.com** and press **Enter**. After the website opens up, go to the top right corner and click **SIGN IN**.

	![](./1079838.jpg)

1. After the sign-in form appears, click on **CREATE AN ACCOUNT**.

	![](./1079842.jpg)

1. Click on **START SUBSCRIPTION FOR FREE** under **FREE \(BASIC\)** Section.

	![](./1079843.jpg)

1. Sign Up page appears, fill the required details in the sign-up form and click the **SIGN UP** button to create an account.

	>Note: Please provide working email ID at the time of registration.

	![](./1079844.jpg)

1. After clicking on the sign up, **Valkyrie Dashboard** appears. To analyze a malicious file or a malware, click on **Analyze New File** option present on the top-right corner, as shown in the screenshot.

	![](./1079845.jpg)

1. The **Analyze File** window appears. Under Analyze with File Upload category, click **Select File** button to upload a malware.

	![](./1079846.jpg)

1. The **Open** window appears, navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Malware\\wiki** folder and select the **wikiworm.exe** malware file and click the **Open** button.

	![](./1079847.jpg)

1. If **File Already Exists** prompt appears, click **RE-ANALYZE FILE**. If the uploaded successfully without any prompt click **Analyze**. In this lab, we are re-analyzing the malware file.

	![](./1079849.jpg)

1. The Valkyrie analyzes the malware, the Valkyrie verdict is displayed as a malware under the **Summary** tab. You can also view the details such as **File Name**, **File Type**, **SHA1**, **MD5**, etc. associated with the analyzed malware as shown in the screenshot. These details will be used in further labs.

	![](./1079850.jpg)

1. In order to view the detailed result for **Static Analysis**, **Dynamic Analysis**, **Precise Detectors**, **File Details**, click on the respective tabs as shown in the screenshot.

	![](./1079851.jpg)

1. You can also export the analysis report in the pdf format, by clicking on **Export Results** **To PDF**. The pdf containing analysis result is shown in the below screenshot.  
	  
	This concludes the demonstration of analyzing malware using Valkyrie. You can document all the acquired information. The observed wikiworm malware details are mentioned below. These details will be used in further labs:  
	
	- File Name: wikiworm.exe
	- File Type: PE32 executable \(GUI\) Intel 80386, for MS Windows
	- SHA1: c8ac1b977d771c89ed7152f0daedb6a3e8b69b24
	- SHA256: 9fd30bda0edf3b10b326703303fa15995a688d200582822ef49422ebac87b7f7
	- MD5: f68872773a88652541bd8d6ca9bda058
	- File size 4 KB
	
	This is the end of the lab, log out and close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1079852.jpg)

In this exercise, you have learnt how to:  

- Analyze Malware using VirusTotal and Maltego
- Analyze Malware using Blueliv Threat Exchange Network
- Analyze Malware using Valkyrie

---

# Exercise 9: IoC Data Collection through External Sources

## Scenario

Indicators of Compromise \(IoCs\) can be collected from external sources that are beyond the organizational perimeter. Following are the major external sources for IoC data collection:  

- Commercial and industry IoC sources: The analyst can gather IoC information from various commercial and industrial sources like security product vendors, law enforcement agencies, threat information sharing sources, etc. Security product vendors like Dell SecureWorks, McAfee, Symantec, RSA, Norse, etc., and Law enforcement agencies like FBI Liaison Alert System \(FLASH\) release IoC updates and alerts on regular basis. The analyst can gather the IoC updates from such vendors by becoming one of its customers or by subscribing to the vendors or law enforcement agencies.
- Free IOC sources: IoC data can be acquired from free and open-source IoC distribution sites. Various IoC specific open source information sharing tools like AlienVault OTX, Blueliv Threat Exchange Network, etc. can be used by the analyst to gather IoC specific information.
- IOC Bucket: IOC Bucket is a free community driven platform dedicated to providing the security community with a way to share quality threat intelligence in a simple but efficient way. IOC Buckets IoCs are developed by the community, reviewed by the community, and distributed for use by the community and the content will always remain free and available. The analyst can use IoC Bucket tool to gather IoC information.

  
**Lab Scenario**  

Indicators of Compromise \(IoCs\) are the pieces of technical data that is used for building tactical threat intelligence. IoCs are the clues or forensic evidence that indicate the potential intrusion or malicious activity in the organizational network. It is the information regarding suspicious or malicious activity that is collected from various sources. IoC information is considered one of the key intelligence input for conducting threat intelligence. As an analyst, you must be capable of collecting IoC data from various external sources which are beyond the perimeter of the network infrastructure. This lab will show you how to collect IoC data using various external sources like Blueliv Threat Exchange Network, ThreatConnect, and IOC Bucket.  
  
**Lab Objectives**  

The objective of this lab is to demonstrate:  

- IoC Data Collection using Blueliv Threat Exchange Network
- IoC Data Collection using ThreatConnect
- IoC Data Collection using IOC Bucket

  
Lab Duration: **25 Minutes**

1. Click Windows10 and click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the **Windows 10** machine then skip to step **3**.

	![](./1079853.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If **Networks** prompt appears once you have logged into the machine, click **Yes**. Alternatively, navigate to **Commands** (**Thunder** icon) menu **Type Text** and click **Type Password**.

	![](./1079871.jpg)

1. Now, we shall perform IoC data collection using **Blueliv Threat Exchange Network**. Open any web browser \(here, **Mozilla Firefox**\) in the address bar of the browser type **https://community.blueliv.com** and press **Enter**.

	![](./1079872.jpg)

1. The **BLUELIV THREAT EXCHANGE NETWORK** page appears. Click **LOG IN** button present at the top-right corner of the window.

	![](./1079873.jpg)

1. **LOG IN** page appears. Enter the login credentials of the **Blueliv Threat Exchange Network** that you have created in the previous exercise and click **LOG IN** button.

	![](./1079874.jpg)

1. By default, the Blueliv landing page appears which provides basic details about the latest threat information and details. Click on **DISCOVER** tab.

	![](./1079875.jpg)

1. The DISCOVER page opens up and this page consists of the details of all the **TRENDING SPARKS**. Sparks is considered as the latest news and notifications about the threat events and activities whose details are submitted by other users.  
	  
	Click on any of the published sparks to explore the details and collect the **IoC data**. \(Here, we clicked on **The "MartyMcFly" investigation: anchors-chain** case spark as an example. You can select any spark as per your interest and the spark list shown in the screenshot may differ\).

	![](./1079876.jpg)

1. After clicking on the desired spark, you can view the details of the spark. In order to view the specific indicators of the spark, scrolling down to **INDICATORS** section where you can view the indicator details like **Hash-SHA256**, **IPv4**, **DOMAIN**, etc. as shown in the screenshot.

	![](./1079877.jpg)

1. After going through the details of the spark and its IoC&rsquo;s, it is the task of an analyst to collect such required threat sparks to build the organization threat intelligence. Click **EXPORT** **--&gt;** **OpenIOC** present on the top-right corner of the **INDICATORS** section to download the spark in OpenIOC format. A **.xml** file will be downloaded.

	![](./1079878.jpg)

1. Firefox download pop-up appears, choose **Save File** radio button and click **OK**.

	![](./1079879.jpg)

1. Leave the File name to default and navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOCs** and click Save to save the file.

	![](./1079880.jpg)

1. Similarly, export the **STIX** format and save the file in the same location with its default name as shown in the screenshot. This concludes the demonstration of IoC data collection using Blueliv Threat Exchange Network. You can document all the acquired information.  
	  
	**Logout** from the Blueliv THREAT EXCHANGE NETWORK page and close all the open Windows.

	![](./1079881.jpg)

1. Now, we shall perform **IoC data collection using ThreatConnect**. Open any web browser \(here, **Mozilla Firefox**\). In the address bar of the browser type **https://www.threatconnect.com** and press **Enter**.

	![](./1079882.jpg)

1. Click on the **Login** tab as shown in the screenshot.

	![](./1079883.jpg)

1. The Login page appears, click on **Sign up for free now!** link.

	![](./1079884.jpg)

1. A **Signup** page appears, scroll down for **Get Started for Free Now** form. Fill the required details to create an account and then click on **GET STARTED FREE** button.  
	  
	Please provide **working email ID** at the time of registration. Once the registration is done, you will receive an activation email, and this email may come immediately, or it may take some time. After receiving the email regarding the activation process, activate your account as instructed in the email in order to use features of the **THREATCONNECT**.

	>Note: If you get any CAPTCHA verification process please verify the captcha.

	![](./1079885.jpg)

1. An account is created successfully, the verification email was sent to your email ID for the activation of the account. Open a new tab login to your email which was provided at the time of registration and open an email received from the **THREATCONNECT** and perform the activation process as instructed in the email.  
	  
	Click **Login Now** button to complete the verification process.

	![](./1079886.jpg)

1. THREATCONNECT Login Page appears as shown in the screenshot, enter the credentials that were provided in the email and click **Sign In**.

	>Note: The Password that was sent to you is a **Temporary password**.

	![](./1079887.jpg)

1. Password Reset Required page appears, type a new password in the **New Password** and **Confirm Password** field and click **SIGN IN**.

	>Note: You should meet the **Password Rules**.

	![](./1079888.jpg)

1. Welcome to ThreatConnect Profile Settings page appears, fill in fields such as **Pseudonym**, **Job Function** and **Organizational Role** and click **Save**.

	![](./1079889.jpg)

1. The welcome pop-up appears as shown in the screenshot, close the pop-up window.

	![](./1079891.jpg)

1. **ThreatConnect Dashboard** page appears. The dashboard consists of latest information on Top Sources by Observations, Latest Intelligence, Top Sources by False Positives, Top Tags, etc. as shown in the screenshot.

	>Note: You can view a detailed information on different intelligence present under Latest Intelligence category by clicking on it.

	![](./1079892.jpg)

1. Click on any incident under **Latest Intelligence** section to view a detailed information on it. In this exercise we are clicking on **Hide and Script: Inserted Malicious URLs within Office Documents' Embedded Videos**. The screenshot will differ if you are clicking on the different incident.

	>Note: When you are performing the lab the Latest Intelligence section may get updated while you are performing this exercise.

	![](./1079893.jpg)

1. The detailed information regarding the selected incident is displayed in the new page. It includes information such as **IP addresses**, **Email Addresses**, **URLs** associated with the incident. Additional information regarding activities and tasks is also present in the report.

	![](./1079895.jpg)

1. This information can be downloaded as a report in the **pdf** format by clicking on the **DOWNLOAD PDF** button present under the name of the incident.

	![](./1079905.jpg)

1. Firefox pop-up window appears to save the file, choose **Save File** radio button and click **OK**.

	![](./1079906.jpg)

1. Save the File in the following location **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOCs** and click **Save**.

	>Note: Leave the file name to default.

	![](./1079908.jpg)

1. After successful download, go to the location where the file is downloaded and double-click to open the file. As an analyst, you can collect the details of the indicators from these reports as well in order to enhance the threat intelligence. The collected incident report can further be used to enhance the threat database of your organizational security systems, thereby enhancing an organization&rsquo;s security posture as a whole. This concludes the demonstration of IoC data collection using ThreatConnect. You can document all the acquired information. **Logout** from all the pages that you have signed in and close all the windows.

	>Note: If How do you want open this file? pop-up appears, choose the **Microsoft Edge** option and click **OK**.

	![](./1079909.jpg)

1. Now, we shall perform IoC data collection using **IOC Bucket**. Open any web browser \(here, **Mozilla Firefox**\). In the address bar of the browser type **https://www.iocbucket.com** and press **Enter**.

	![](./1079911.jpg)

1. The IOC Bucket landing page appears where you can see a search bar and a **Search** button. You can look for a specific malware or IoC&rsquo;s in the community network by entering the malware keyword or IoC parameter in the search bar and clicking the **Search** button.  
	  
	For example, we shall attempt to collect the IoCs related to the most notorious **WannaCry** ransomware. Type **WannaCry** in the search bar and click the **Search** button.

	![](./1079912.jpg)

1. This search will extract the IoC&rsquo;s that are associated with the provided query. In the below screenshot, you can see that the search results list two matches for **WannaCry** ransomware. Click on the **first result** to view its complete IoC details.

	![](./1079913.jpg)

1. **IOC Details** window appears as shown in the screenshot. You can view the details of Indicators of Compromise like sha1, along with the short and long description details, etc. After going through the details of the IoC&rsquo;s, it is the task of an analyst to collect such required threat IoCs to build the organization threat intelligence.  
	  
	Click **Download IOC** button to download the indicator.

	![](./1079914.jpg)

1. Firefox download pop-up appears, choose **Save File** radio button and click **OK**.

	![](./1079915.jpg)

1. Save the file in the following location **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOCs** and click **Save**.  
	  
	This concludes the demonstration of IoC data collection using IOC Bucket. You can document all the acquired information. This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1079916.jpg)

In this exercise, you have learnt how to perform:  

- IoC Data Collection using Blueliv Threat Exchange Network
- IoC Data Collection using ThreatConnect
- IoC Data Collection using IOC Bucket

---

# Exercise 10: IoC Data Collection through Internal Sources

## Scenario

Indicators of Compromise \(IoCs\) can be collected from internal sources that are beneath the organizational perimeter. These internal IoCs can be collected either by performing network monitoring and scanning operations or can be gathered by performing Threat detection and threat hunting operations in the network infrastructure. Following are some of the crucial IoC information that can be collected from internal sources:  

- Unusual outbound network traffic
- Geographical anomalies
- Multiple login failures
- Increase in database read volume
- Signs of DDoS activity
- Large HTML response size
- Unusual DNS request
- Suspicious registry or system file changes
- Unexpected patching of systems
- Unusual activity through the privileged user account

The analyst can use various network monitoring or threat detection tools to identify and gather such internal IoC&rsquo;s.  
  
**Lab Scenario**  

As an analyst, you must be capable of collecting internal IoC data from various sources as well. In the previous lab, we have learnt how to collect IoC data from external sources and in this lab, we will learn how to collect the IoC data from the various network security establishments present within the network perimeter. This lab will show you, how to collect internal IoC data using various tools like Splunk Enterprise and Valkyrie Unknown File Hunter.  
  
**Lab Objectives** 
 
The objective of this lab is to demonstrate:  

- Internal IoC Data Collection using Splunk Enterprise
- Tools demonstrated in this lab are available in D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing
- Internal IoC Data Collection using Valkyrie Unknown File Hunter

Lab Duration: **40 Minutes**

1. Click Windows10 and click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the **Windows 10** machine then skip to step **3**.

	![](./1079917.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If **Networks** prompt appears once you have logged into the machine, click **Yes**. Alternatively, navigate to **Commands** (**Thunder** icon) menu **Type Text** and click **Type Password**.

	![](./1079918.jpg)

1. Now, we shall perform internal IoC data collection using **Splunk Enterprise**. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Splunk Enterprise** and double-click **splunk-7.1.1-8f0ead9ec3db-x64-release.msi**.

	![](./1079919.jpg)

1. Splunk Enterprise Installer window appears, in the **Default Installation Options** page, check the **license agreement** check-box as shown in the screenshot and click **Next**.

	![](./1079920.jpg)

1. In the **Splunk Enterprise Setup** window, set Password field as **Pa$$w0rd** and confirm it by retyping in the Confirm Password field, then click **Next**.

	![](./1079921.jpg)

1. Click **Install** in the next window.

	![](./1079922.jpg)

1. The installation process begins and this process may take some time. If the User Account Control pop-up appears, click **Yes**.

	![](./1079923.jpg)

1. After the installation is successful, leave the **Launch browser with Splunk Enterprise** checkbox checked to launch the Splunk Enterprise. Click **Finish**.

	![](./1079924.jpg)

1. How do you want to open this? a pop-up appears to choose the browser of your choice and click **OK**. In this exercise, we are choosing the **Mozilla Firefox** browser.

	![](./1079925.jpg)

1. The Splunk enterprise login page appears. Type **admin** as user and **Pa$$w0rd** as password and click **Sign In** button to sign in as admin.

	![](./1079926.jpg)

1. If Help us improve Splunk software pop-up appear, click **Skip**.

	![](./1079927.jpg)

1. The Splunk Enterprise dashboard window appears by default. Click on **Add Data** icon as shown in the screenshot.

	>Note: If a pop-up window related to web application tour appears, continue with the tour or click **Skip** in order to continue with the lab.

	![](./1079928.jpg)

1. The Add Data page appears. Click **Monitor** icon.

	![](./1079929.jpg)

1. Click **Local Event Logs** from the left-pane. In the **Select Event Logs** list, select **Application** and click **Next** at the top of the window.

	![](./1079930.jpg)

1. In the **Input Settings** page, ensure the desktop name in the Host field value under the **Host** section and click **Review** at the top of the window.

	![](./1079931.jpg)

1. In the **Review** page, review the configuration and click the **Submit** button at the top of the window.

	![](./1079932.jpg)

1. After the local event logs input has been successfully created, click **Start Searching** button.

	>Note: If a pop-up window related to web application tour appears, continue with the tour or click **Skip** in order to continue with the lab.

	![](./1079933.jpg)

1. A New Search window appears as shown in the screenshot. Minimize the browser window.

	![](./1079934.jpg)

1. Now, before performing a search for internal threats or internal IOC&rsquo;s in the host machine, we shall manually execute a malware in order to ensure the threat detection by Splunk Enterprise. For executing the malware, navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Malware\\wiki** and double-click **wikiworm.exe**.  
	  
	A pop-up window appears displaying **Don&rsquo;t worry &ndash; be happy! :\)** as shown in the screenshot. Do not close the pop-up window, indicating that the malware is executed in your machine. Minimize the File Explorer window.

	![](./1079935.jpg)

1. You can also confirm that the malware is executed in your machine by opening **Task Manager** and observing the running processes. Minimize the Task Manager window.

	![](./1079936.jpg)

1. Now, we shall perform the search using **Splunk Enterprise**. Switch back to Splunk web page and in the **New Search** window&rsquo;s search bar, type **wikiworm.exe** set the time frame as **Last 15 minutes** and click the **Search** icon. The result for this search will be as shown in the screenshot.

	>Note: If search results do not show any events, wait for few minutes and click the **Search** icon again.

	![](./1079937.jpg)

1. Since we have analyzed this **wikiworm.exe** as a malicious malware in the previous malware analysis labs, here, we will consider this wikiworm.exe as a **threat** and we shall set this as threat indicator for real-time threat detection.  
	  
	Click **Save As** --&gt; **Alert** as shown in the screenshot, to set the wikiworm.exe as a threat indicator for threat detection.

	![](./1079938.jpg)

1. In the **Save As Alert** window, enter the details of the alert like Title, Description and set the Alert type as **Real-time**. Click **\+ Add Actions** drop-down list and select **Add to Triggered Alerts**. After the action is added, select the **Severity** of the action as **High** and click **Save**.

	>Note: Scroll down to set the other options.

	![](./1079939.jpg)

1. The Alert has been saved window appears. Click **View Alert**.

	![](./1079940.jpg)

1. Review the created alert. Now, as we have configured **wikiworm.exe** as an indicator to trigger an alert, we shall test the threat detection by executing the **wikiworm.exe** again.

	![](./1079941.jpg)

1. For executing the malware first click **OK** on the pop-up window of the wikiworm malware, then navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Malware\\wiki** and double-click **wikiworm.exe**. A pop-up window appears displaying Don&rsquo;t worry &ndash; be happy! :\) as shown in the screenshot, click **OK** to close the pop-up window after executing the malware.

	![](./1079942.jpg)

1. To view the triggered alerts navigate to **Activity** --&gt; **Triggered Alerts** as shown in the screenshot in the Splunk page.

	![](./1079943.jpg)

1. In the **Triggered Alerts** page, you can observe that the alert has been trigged for the configured wikiworm.exe malware with the configured severity as shown in the screenshot.  
	  
	In this task, we have considered only Local Event Logs as input sources for performing real-time indicators of compromise detection, however, as an analyst, you can configure the Splunk Enterprise tool as per your requirement for collecting internal IoC data. This concludes the demonstration of internal IoC data collection using Splunk Enterprise. You can document all the acquired information. Logout from the web application and close all the open windows.

	![](./1079948.jpg)

1. Now, we shall perform the of internal IoC data collection using **Unknown File Hunter**. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Valkyrie Unknown File Hunter** and double-click **UnknownFileHunter.exe**.

	>Note: If the User Access Control pop-up appears, click **Yes**.

	![](./1079949.jpg)

1. End User License Agreement appears, click **I Accept** button.

	![](./1079951.jpg)

1. After the completion of installation, the **Unknown File Hunter** window appears, click on **Scan Now** as shown in the screenshot.

	![](./1079952.jpg)

1. Before configuring and starting the scan, execute the malware by navigating to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Malware\\wiki** and double-click **wikiworm.exe**.  
	  
	A pop-up window appears displaying Don&rsquo;t worry &ndash; be happy! :\) as shown in the screenshot, indicating that the malware is executed in your machine. Do not close the pop-up window.

	![](./1079953.jpg)

1. After executing the malware, switch back to the Unknown File Hunter. In the **Start Scan** **Wizard** window, select **This Computer** option under Select Scan Targets as shown in the screenshot.

	![](./1079954.jpg)

1. Under Select Local Scan Mode, click on **Quick Scan**. Unknown File Hunter starts scanning your system for malicious files. Scanning takes approximately **10 minutes**.

	![](./1079955.jpg)

1. Once the scanning is completed, a Scan Result pop-up window appears. You can observe that there is a **Malicious File** identified under **Threat Detection Summary** section indicating the detection of malware in the local machine. Click **Yes**.

	>Note: If **Submit to Valkyrie** pop-up appears, close the window.

	![](./1079956.jpg)

1. To generate a detailed scan report, click on **Reports** tab and in the drop-down list, click **Per Device** option.

	![](./1079959.jpg)

1. The Scan Report is shown in the screenshot. In this task, we have used Unknown File Hunter to identify the threats of internal IoC&rsquo;s present in the system. This concludes the demonstration of internal IoC data collection using **Unknown File Hunter**. You can document all the acquired information.  
	  
	This is the end of the lab, close all the open windows.

	![](./1079961.jpg)

In this exercise, you have learnt how to perform:  

- Internal IoC Data Collection using Splunk Enterprise
- Internal IoC Data Collection using Valkyrie Unknown File Hunter

---

# Exercise 11: Data Collection through Building Custom IoC’s

## Scenario

Analysts can build their own indicators based on particular patterns of observations and collect the data from that custom IoCs. These indicators can be built using the OpenIOC framework and then used with the extensible XML schema for scanning the hosts for any signs of threats. It is used in an advanced scanning process to find a specific type of vulnerability whenever it gets active in the system.   
The analyst can use tools like IOC Editor, IOC Bucket, etc. to build organization Specific TI based Custom IoCs. The analyst can also write YARA rules to build custom IoCs.  
  
**Lab Scenario**  

While collecting the IoC data for building threat intelligence, the next step an analyst must be able to do is create custom IoCs. The custom builds IoCs can be used by the analyst to collect internal as well as external data. Building custom IoCs not only assist in the development of threat intelligence but also helpful in disseminating the IoCs to the communities. These IoCs can also be shared between the agencies and organizations for collaborations and enhancements by combining intelligence to achieve effectiveness in threat detection. In this lab, as a threat analyst, you will build custom IoCs using tools like IOC Editor and IOC Bucket.  
  
**Lab Objectives**  

The objective of this lab is to demonstrate:  

- Building custom IOCs using IOC Editor
- Building custom IOCs using IOC Bucket

Lab Duration: **40 Minutes**

1. Click Windows10 and click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the Windows 10 machine then skip to step **3**.

	![](./1079962.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If Networks prompt appears once you have logged into the machine, click **Yes**. Alternatively, navigate to **Commands** (**Thunder** icon) menu **Type Text** and click **Type Password**.

	![](./1079963.jpg)

1. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOC Editor** and double-click **Mandiant IOCe.msi**. The Mandiant IOCe window appears, click **Next** and follow the wizard steps to install Mandiant IOCe.

	>Note: The User Account Control pop-up appears, click **Yes**.

	![](./1079964.jpg)

1. In the last step of the installation wizard, click **Close**.

	![](./1079966.jpg)

1. After the installation is complete, click **Windows** icon at the bottom-left corner of the screen and type **Mandiant IOCe** and click on the search result to launch **IOC Editor**.

	![](./1079967.jpg)

1. The **IOC Editor** opens. In the **Browse For Folder** pop-up window, navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOCs** folder and click **OK**.

	![](./1079968.jpg)

1. **IOCe 2.2.0** window appears. By default, you will find **Ransom-WannaCry\_Updated IoC** file \(which we have downloaded from IOC Bucket in the previous lab\) in the left pane. Click on the **Ransom-WannaCry\_Updated** file to view the content in the right-pane as shown in the screenshot.

	![](./1079972.jpg)

1. After going through the details of the Ransom-WannaCry\_Updated file, click **File** --&gt; **New** --&gt; **Indicator** to create a new indicator.

	![](./1079974.jpg)

1. A new indicator will be created in the left pane. In the right-pane, write the basic details of the indicator like Name, Author, and Description as shown in the screenshot.

	![](./1079976.jpg)

1. Now, we have to write the logic for the indicator under **Add:** section. Recollect the wikiworm malware details you have gathered from malware analysis labs.  
	
	- **File Name: wikiworm.exe**
	- **File Type: PE32 executable \(GUI\) Intel 80386, for MS Windows**
	- **SHA1: c8ac1b977d771c89ed7152f0daedb6a3e8b69b24**
	- **SHA256: 9fd30bda0edf3b10b326703303fa15995a688d200582822ef49422ebac87b7f7**
	- **MD5: f68872773a88652541bd8d6ca9bda058**
	- **File size: 4 KB**
	
1. In the Add: section, by default, **&hellip;.OR** will be available. Right-click on **&hellip;.OR** and navigate and open to **Add Item** --&gt; **FileItem** --&gt; **File Name**.

	![](./1079979.jpg)

1. A text box appears, type **wikiworm** and press **Enter**.

	![](./1079980.jpg)

1. The File Name contains wikiworm appears indicating the **File Name** is saved to wikiworm.

	![](./1079981.jpg)

1. Again right-click on **&hellip;.OR** and navigate and open to **Add Item** --&gt; **FileItem** --&gt; **File PE Type**.

	![](./1079982.jpg)

1. A text box appears, type **PE32** and press **Enter**. The File PE Type contains PE32 appears indicating the File PE Type is saved to PE32.

	![](./1079983.jpg)

1. Similarly, add **File MD5** as **f68872773a88652541bd8d6ca9bda058**.

	![](./1079984.jpg)

1. Similarly, add **File Size** as **4kb**.

	![](./1079985.jpg)

1. Similarly, add **File Sha1sum** as **c8ac1b977d771c89ed7152f0daedb6a3e8b69b24**.

	![](./1079986.jpg)

1. Similarly, **add File Sha256sum** as **9fd30bda0edf3b10b326703303fa15995a688d200582822ef49422ebac87b7f7**.

	![](./1079987.jpg)

1. Click **Save** after writing the logic. The example is shown in the screenshot.

	![](./1079988.jpg)

1. The indicator will be saved in the **.ioc** format in the **IOC Directory** that we have set at the beginning. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOCs folder** to view the saved IOC file. This custom builds IOC will be used in further labs to disseminate to the threat exchange communities like AlienVault OTX, Blueliv Threat Exchange Network, IOC Bucket, etc.  
	  
	In this task, you have successfully completed building custom IoC related to wikiworm using IOC Editor. You can explore the tool and its features and build custom IoC&rsquo;s as per your organization requires. This concludes the demonstration of building custom IOCs using IOC Editor. You can document all the acquired information.  
	  
	Close all the open Windows.

	>Note: The file name will vary while you are performing the lab.

	![](./1079989.jpg)

1. Now, we shall perform building custom IOCs using **IOC Bucket**. Open any web browser \(here, **Mozilla Firefox**\). In the address bar of the browser type **https://www.iocbucket.com/openioceditor** and press **Enter**.

	![](./1079991.jpg)

1. OpenIOC Online Editor Beta page appears. Click **File Items** button as shown in the screenshot.

	![](./1079992.jpg)

1. A FileItem tray appears. Click **File Name**.

	![](./1079993.jpg)

1. Enter new value text box appears in the middle pane, type **wikiworm** and press **Enter**.

	![](./1079995.jpg)

1. After successfully adding the File Name, again click **File Items** button, scroll down in the **FileItem tray** and click **File PE Type**.

	![](./1079996.jpg)

1. Enter new value text box appears, type **PE32** and press **Enter**.

	![](./1079997.jpg)

1. Similarly add the indicator details like **File Size** as **4kb**, **File MD5** as **f68872773a88652541bd8d6ca9bda058**, **File Sha1sum** as **c8ac1b977d771c89ed7152f0daedb6a3e8b69b24** and **File Sha256sum** as **9fd30bda0edf3b10b326703303fa15995a688d200582822ef49422ebac87b7f7**.  
	  
	After entering all the values of the malware, click **Save IOC** button. An example of this is shown in the screenshot.

	![](./1079999.jpg)

1. Firefox pop-up window appears, click **OK** to save the file with the name **New-Indicator.ioc**.

	![](./1080001.jpg)

1. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOCs** folder and click **Save**.

	![](./1080002.jpg)

1. The New-Indicator.ioc will be downloaded in **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\IOCs** folder.  In this task, you have successfully completed building custom IoC related to wikiworm using IOC Bucket. You can explore the tool and its features and build custom IoCs as per your organization requires. This concludes the demonstration of building custom IoCs using IOC Bucket. You can document all the acquired information.  
	  
	This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./1080003.jpg)

In this exercise, you have learnt how to:  

- Build custom IOCs using IOC Editor
- Build custom IOCs using IOC Bucket

---

# Exercise 12: Structuring/Normalization of Collected Data

## Scenario

Structuring/normalization is a process of structuring the unstructured data to make it sorted and usable by the humans as well as by automated machine tools for intelligence consumption. The collected data may be in different formats or in the form of the unstructured bulk of data. Hence, to make the collected data usable and rich in intelligence, the data needs to be in a structured form.  
  
Lab Scenario  
In a structured form of bulk data collection, the data collection is restricted to some of the organization specific parameters. As an analyst, you must employ filtering, tagging and queuing technique to sort out the relevant and structured data from the large amounts of unstructured data. Structuring/normalization of data is performed to reduce the data redundancy thus, improving data acceptability and data integrity. In this lab, as an analyst, you are required to generate structured data formats such as STIX or CybOX from unstructured files using The STIX Project Generator.  
  
**Lab Objectives**  

The objective of this lab is to demonstrate:  

- Data Structuring and Format Conversion using The STIX Project

Lab Duration: **10 Minutes** 

1. Click on ParrotSecurityCTIA to switch to the **Parrot Security** machine.

2. Click the **MATE Terminal** icon at the top of the **Desktop** window to open a **Terminal** window

3. A **Parrot Terminal** window appears. In the terminal window, type **sudo su** and press **Enter** to run the programs as a root user.

4. In the **[sudo] password for Analyst** field, type **toor** as a password and press **Enter**.

	>[!note] The password that you type will not be visible.	

	![](./3ch2sdvm.jpg)

5. Navigate to the **openioc-to-stix** folder by typing **cd openioc-to-stix** and press **Enter**, as shown in the screenshot.

	![](./oabdw0mh.jpg)

6. After navigating to the desired folder, type **pip3 install .** and press **Enter** to install required files to run the tool successfully.

	![](./cbcjsvq3.jpg)

7. After the successful completion of installation, type **python3 openioc-to-stix.py -i &lt;OpenIOC XML file&gt; -o &lt;STIX XML file&gt;** and press **Enter** to convert a file from **OpenIOC** format to **STIX** format.  
	  
	Here, OpenIOC XML file path is **/home/Analyst/openioc-to-stix/examples/ccapp.ioc.xml** and STIX XML file path is **/home/Analyst/Desktop/ccapp.stix.xml**.

	![](./ftb1lz5u.jpg)

8. A file is converted to **STIX** format successfully. Type **cd /home/Analyst/Desktop** and press **Enter** to naviagate to the Desktop where the **ccapp.stix.xml** is saved.. To view the file in the editor, type **pluma ccapp.stix.xml** and press **Enter**.

	![](./p35tzgzi.jpg)

9. The file will open in the editor as shown in the screenshot. As an analyst, you can also structure the unstructured data using tools like **IOC Editor**, etc. This concludes the demonstration of the structuring of collected data using **STIX project**. This is the end of the lab, close all the open windows.

	>Note: **Do not Cancel the Lab session until you complete all the Exercises of this module.**

	![](./5cwsgf0s.jpg)

In this exercise, you have learnt how to perform:  

- Data Structuring and Format Conversion using The STIX Project

---

# Exercise 13: Bulk Data Management and Visualization

## Scenario

Bulk data is the continuous collection of large volumes of data from various sources in various formats in order to achieve better insights that can lead to developing effective intelligence. Bulk data collection is associated with the concepts like volume, velocity, variety, variability, complexity, distributed processing, distributed storage, etc. so managing the collected bulk data as per the organizational requirement is a crucial step while building threat intelligence.  
Data visualization is the graphical or pictorial representation of the data and statistical information. It enables the analyst to easily understand the complex data structures, statistical details, and patterns of the information presented which might go undetected if in a textual format. The visual representation is versatile enough for deeper analysis and querying of the data and its easy manipulation, which is not possible with the traditional graphs and excel spreadsheets. The data is represented in a more sophisticated manner using infographics, maps, gauges and meters, detailed bars, and pie charts. The analyst can use data management and visualization tools to perform this task.  
  
**Lab Scenario**  

Till now, we have discussed various types of data collected from various sources. For building an effective threat intelligence, as an analyst, you must gather much more data from various other sources including the ones mentioned in the previous labs. In this lab, we will perform management and visualization of collected bulk datasets. For performing this lab, we shall assume that by this stage, the analyst has collected all the required data from various sources. We shall use the Tableau tool to manage and visualize the collected bulk data. Since the bulk data that is collected can vary depending on organizational requirement, in this lab, we shall use the custom survey data related to cyber data breaches and demonstrate to manage and visualize the details regarding individuals affected as per the data feed.  
  
**Lab Objectives**  

The objective of this lab is to demonstrate:  

- Bulk Data Management and Visualization using Tableau

Lab Duration: **20 Minutes**  

1. Click Windows10 and click **Ctrl+Alt+Delete**.

	>Note: If you are already logged in the Windows 10 machine then skip to step **3**.

	![](./1080017.jpg)

1. In the Password field, type **Pa$$w0rd** and press **Enter** to login.

	>Note: If **Networks** prompt appears once you have logged into the machine, click **Yes**. Alternatively, navigate to **Commands** (**Thunder** icon) menu **Type Text** and click **Type Password**.

	![](./1080019.jpg)

1. To install Tableau, navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Tableau** and double-click **TableauDesktop-64bit-2018-1-2.exe**. The Tableau Setup window appears. **Check the license agreement** check-box and click **Install** button to install Tableau.  
	  
	Follow the wizard-driven installation steps \(by selecting default options\) to install Tableau.

	>Note: The User Account Control pop-up appears, click **Yes**.

	![](./1080021.jpg)

1. Tableau Registration pop-up appears, register with your own details, and provide working email ID, and click **Start trial now**.

	![](./1080023.jpg)

1. **Tableau &ndash; Book1** window appears. Close the **Welcome** pop-up message box. In the left pane, click **More...** present under **To a File** section as shown in the screenshot.

	![](./1080025.jpg)

1. The **Open** window appears. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Bulk Data**, select **HHSCyberSecurityBreaches.csv** file and click **Open** button to open the .csv file in Tableau.

	![](./1080026.jpg)

1. After adding the file, the Tableau interface displays the file data in a spreadsheet view. You can view the records that are present in the file you just added.

	![](./1080028.jpg)

1. Now, we shall add another dataset file to the project by clicking on **Add** link present in the top-left pane. Add a Connection menu appears. Under **To a File section**, click **More&hellip;**

	![](./1080029.jpg)

1. The Open window appears. Navigate to **D:\\CTIA-Tools\\CTIA Module 04 Data Collection and Processing\\Bulk Data**, select the **breaches.csv** file and click **Open** button to open the .csv file in Tableau.

	![](./1080030.jpg)

1. After you add the file to the project, Tableau interface will display the merged data from both the files you just added to the project.

	![](./1080031.jpg)

1. Click on **InnerJoin** icon as shown in the screenshot to view and apply various Join options, like Inner, Left, Right and Full Outer, available with the dataset in order to view the contents of the dataset on file preference. The Join option will combine the data results from both the dataset either completely or partially.

	![](./1080032.png)

1. You can apply filters to the dataset results to sort out and view the output for specific parameters. Click on **Add** under **Filters** on the top-right corner of the window. **Edit Data Source Filters** **dialogue** box appears, click on **Add&hellip;.** in the **Add Filter** selection list, choose the filters you wish to apply to the dataset result \(here, we select the field **Individuals Affected**\) and click on **OK** in the Add Filter selection box.

	![](./1080033.jpg)

1. **Filter \[Individuals Affected\]** window appears. Under the Range of values tab, set the range of values as per your requirement \(here, we have set the range as 1500 to 2000\). After setting the range, click the **OK** button.

	![](./1080034.jpg)

1. In the **Edit Data Source Filters** window, you can observe that the Individuals Affected filter is applied under Filter column and the ranges from **1,500** to **2,000** are set under the **Details** column. Click **OK** in the Edit Data Source Filter dialogue box.

	![](./1080035.jpg)

1. The bulk dataset will be filtered and sorted according to the configured filter parameters. An example is shown in the screenshot.

	![](./1080036.jpg) 

1. You can apply many more filters and perform other analytical operations on the collected bulk datasets using the operational features available in the **Tableau** tool. After performing the analytical operations in order to manage the acquired bulk dataset, we can visualize the datasets using Tableau tool. Firstly, we need to **remove all** the applied filters for the imported datasets. To do this, click on **Edit** option under **Filters** present at the top-right corner of the window. **Edit Data Source Filters** window appears, select the applied filter in the **Edit Data Source Filters** window and click **Remove** and then **OK**. The applied filter will be removed.

	![](./1080038.jpg)

1. Click on **Tableau** icon present on the top-left corner of the window. In the left pane, under **Connect** --&gt; **Saved Data Sources**, click **World Indicators**.

	![](./1080039.jpg)

1. The **Sheet1** page appears. In the left pane, click on **HHSCyberSecurityBreach.csv** under **Data** section. In the left pane, navigate to **Dimensions** --&gt; **HHSCyberSecurityBreach.csv** --&gt; **State** --&gt; **Add to Sheet**. To add and visualize the State dimension in the worksheet.

	![](./1080040.jpg)

1. After adding the **State dimension** to the worksheet, you can see that the State dimension is added in the sheet and also **Columns** and **Rows** are set to **Longitude** \(generated\) and **Latitude** \(generated\) respectively.

	![](./1080041.jpg)

1. Then again, in the left pane, navigate to **Dimensions** --&gt; **breaches.csv** --&gt; **State \(breaches.csv\)** --&gt; **Add to Sheet**. To add and visualize the State \(breaches\) dimension in the worksheet.

	![](./1080042.jpg)

1. After adding the dimensions to the sheet, now we shall visualize the actual data that we want to analyze, i.e. **Individuals Affected**. First, we shall analyze the individuals affected by the **HHSCyberSecurityBreach.csv** data. So, to do this, in the left pane, navigate to **Measures** --&gt; **HHSCyberSecurityBreach.csv** --&gt; **Individuals.Affected**. In the right pane named **Show Me**, the visualization charts appear. Click on the **packed bubbles** chart icon to visualize the intended data. The result will be visualized in the middle-pane as shown in the screenshot.

	![](./1080043.png)

1. Click on the **Stacked bars** icon in the Show Me tray to visualize the data in the stacked bars chart.

	![](./1080044.png)

1. Now, we shall visualize the individuals affected from the **breaches.csv** sheet. So, to do this, in the left pane, navigate to **Measures** --&gt; **breaches.csv** --&gt; **Individuals Affected**. In the right-pane named **Show Me**, the visualization charts appear. Click on the **packed bubbles** chart icon to visualize the intended data. The result will be visualized in the middle-pane as shown in the screenshot.

	![](./1080045.jpg)

1. Click on the **treemaps** icon in the **Show Me** tray to visualize the data in treemaps chart. You can add as many dimensions or measures as per your requirement, to visualize and analyze the collected data in order to extract intended threat intelligence.  
	  
	This concludes the demonstration of bulk data management and visualization using Tableau. You can document all the acquired information. This is the end of the lab, close all the open windows.

	![](./1080046.png)

In this exercise, you have learnt how to perform:  

- Bulk Data Management and Visualization using Tableau

***
