## Exercise 4: Proactively Investigate Potential Threats, Misconfigurations, and Suspicious Activities with KQL Queries 

**Task 1:** Navigate to Sentinel Hunting and Run all queries<br>
As in Task 1, we will be proactively hunting for Indicators of Attack in Sentinel. In that task we were doing so visually through the use of dashboards. Here, we will use built-in KQL queries to identify signs of potential problems.
1.	From the Azure Sentinel homepage, click on **Hunting.**

2.	In the pane that opens, click on Hunting.<br>

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt01.PNG
)<br><br>

3.	Examine the Queries in the middle pane. These are built-in KQL queries provided to help you hunt for adversaries in your environment. Pay attention to the description and also special attention to the Tactics column. You may learn more about a particular tactic by moussing over it for a description. This column helps you understand which part of the attacker kill chain you may insert yourself in with the query. For example, by examining **Hosts with new logons**, you may be able to detect Lateral Movement in the environment.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt02.PNG
)<br><br>

4.	By running all the built-in queries, you have a quick indicator of specific areas of concern. These may form a ready-made map of where your time should be spent hunting in any given point in time.
5.	Click **Run displayed queries.**
![alt text](Lab/LAb04/../../screenshots/rundiisplayquery.png)
<br><br>

6.	Look at the Results column. Note that several of these queries have returned results. These require further investigation. You will want to help your customers pay special investigative attention to the results of queries like **New processes observed in last 24 hours**, and **uncommon processes – bottom 5%**. These can be indicators of compromise that are often missed.

**Task 2. Run Several Single Hunting Queries and Examine the Output in Detail**<br>

In this Task, we will run several single queries to hunt for indicators of compromise.<br>

**Step 1:** Run the New processes observed Query and Examine the Output<br>
1.	Search for the Query  **New processes observed in the last 24 hours** and click on it.
2.	This brings up information about this Hunting query on the right side of the screen.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt04.PNG
)<br><br>

3.	**Optional:** for background information, you may click on read more on mitre.com. This is an excellent knowledge base of adversary tactics and techniques that have been documented in the wild.
4.	Click **Run Query** and then click **View Results**. This launches the Logs page, pre-populates the KQL query, and displays the results.
![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt05.PNG
)<br><br>

5.	Briefly examine the table of results. Notice that it features HostCount  and FileName columns of information. From the results, we can see that there have been a number of new processes launched across the estate in the last 24 hours.
6.	This may be a sign of normal, benign programs being run. However, in normally stable environments, these new processes could provide an indication of an unauthorized/malicious binary that has been installed and run. Look closely at the results as shown below.<br>(**The results on this phase may looks differently on your side!** )
![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt06.PNG
)<br><br>

7.	Right away we might notice some suspicious activity. For purposes of our lab, let’s focus on the highlighted process above and the ones like it. These are processes we do not normally recognize – and they may very well be nefarious. Certainly, we need to investigate further.
8.	Note that we have identified a protentially dangerous process that otherwise would have gone unnoticed in the environment. This can be an early indicator of compromise – and early detection is key to being able to create a meaningful response.
9.	Click on **Azure Sentinel – Hunting** at the top to return to he Hunting section.
![alt text](/Labs/LAB04/screenshots/hunt6a.png)<br><br>

**Step 2:** Run the Hosts with new logons Query and Examine the Output<br>
1.	Search for and click on the query **Hosts with new logons.**

2.	This brings up information about this Hunting query on the right side of the screen

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt08.PNG
)<br><br>

3.	Notice the description.
4.	Scroll down to view the query and the tactics.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt09.PNG
)<br><br>

5.	**Optional**: for background information, you may click on read more on mitre.com. This is a knowledge base of adversary tactics and techniques that have been documented in the wild.
6.	Click **Run Query** and then click **View Results.** This launches the Logs page, pre-populates the KQL query, and displays the results.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt10.PNG
)<br><br>

7.	Briefly examine the query. The query is asking for successful and failed logon events, creating a union, setting some time parameters, joining several tables, and setting some output parameters.
8.	Briefly examine the table of results. Notice that it features the projected attributes Name and Hostcount. From the results, we can see that a subset of computers have indeed received recent (new) logon activity.
9.	Your output may look slightly different, but right away we might notice some suspicious activity. Multiple domain controllers (DCs) have received new logons. This bears further investigation. New logons to DCs are typically rare; DCs also represent high-value attack targets.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt11.PNG
)<br><br>

**Task 3**: Craft and Execute a Hunting Query to Investigate the New DC Logons<br>

1.	In this Task, we want to investigate the accounts that have logged onto the DCs in the last day.
2.	Click the **Plus** (+) sign next to New Query 1.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt12.PNG
)<br><br>

3.	In the new query window, copy the text of this query to investigate the accounts that have logged onto the DCs:

```powershell
SecurityEvent
| where EventID == 4624
| where TimeGenerated >= ago(3d)
| where Computer startswith "DC01" or Computer startswith "DC03" or Computer startswith "DC04"
| where Account !endswith "$" and Account != @"NT AUTHORITY\LOCAL SERVICE" and Account != @"NT AUTHORITY\SYSTEM"
| summarize count() by Computer, Account, LogonTypeName
```
4.	Examine the output. Here you would hunt for any Accounts that you would not expect to log onto DCs. For example, an account that did not belong to a member of the IT staff (and specifically an Active Directory administrator) would throw a red flag to take action. You could also additionally hunt for discrepancies in logon times, for example, by modifying the query in various ways.

5.	In the query results, do you see any accounts that you would flag with your customer? In the example below, we see an account called briandel having logged into DC01. That is definitely an indicator of compromise. We would need, in this case, to take action against both the account and potentially inside of Active Directory. We could even be in an incident response type of scenario.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/brain.png
)<br><br>

6.	At the top of the page, click **Azure Sentinel – Hunting** to return to the Hunting pane.

![alt text](/labs/LAB04/screenshots/hunt6a.png)<br><br>

**Task 4: Craft and Execute a Unique Hunting Query to Investigate a Distinct Security Concern**<br>

In this Task, you will pick up where the Insecure Protocols dashboard left off. You will craft a query to hunt for the use of Legacy Protocols against Azure AD. One source of legacy protocols is often, but not exclusively, the use of mail browsers accessing Office 365/Exchange Online. In reality, you could make this a dashboard, or an extension of the Insecure Protocols dashboard. But in the interest of time, here you will craft this activity as a Hunting Query.<br>
1.	From within the Hunting section of the portal, Click on the + **New Query** button<br>

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt15.PNG
)<br><br>


2.	On the Create custom query page, Fill in the following information<br>
**Name:** Azure AD Legacy Protocol – Admin[Number]<br>
[Where Admin1 is the name of your logon. For Example, if my logon is Admin 43, then the Name field would read **Azure AD Legacy Protocol – Admin43.**]<br>
**Description:** Hunt for Legacy Protocols across the estate hitting Azure AD.<br>
**Custom query:**

```powershell
SigninLogs
| where ClientAppUsed in ('Other clients; Older office clients', 'Other clients', 'Other clients; IMAP', 'Other clients; POP', 'Authenticated SMTP')
| where TimeGenerated >ago(30d)
| summarize count() by UserPrincipalName, IPAddress, ClientAppUsed
```
![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt16.PNG
)<br><br>

In this example, my user name is User43.<br>
3.	Leave the **Entity mapping** fields blank.<br>
4.	Add the Tactics that you think best match the attacker tactics you are hunting for. For example, **Initial Access, Privilege Escalation and Credential Access** are all risks of using Legacy Protocols.<br>
5.	Click **Create.**<br>
6.	On the main Hunting page, examine your new query. (If not displayed use the search)<br>

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt17.PNG
)<br><br>

7.	Click **Run displayed queries** to include your new query in the overall Hunting experience.
8.	Note: If you receive an exclamation point for the result, do not worry. This is an intermittent known issue and should be ignored for now.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt18.PNG
)<br><br>

10.	Click on your new query, click **Run Query** and then click **View Results**.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt19.PNG
)<br><br>

11.	On the following page, examine the output. You are now able to Hunt for Users and IP Addresses that are using Legacy Protocols to access Azure AD; you also know the actual protocol used (IMAP, POP, etc.). Finally, the advantage of creating a Hunting Query is that anyone in your company can now easily reuse your work to hunt for misconfigurations or indicators of attack.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt20.PNG
)<br><br>

12.	At the top, click **Azure Sentinel – Hunting.**

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB04/screenshots/hunt21.PNG
)<br><br>

