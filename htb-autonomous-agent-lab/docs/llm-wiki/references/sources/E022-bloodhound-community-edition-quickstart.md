<!-- source: https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart
     fetched_from: https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart
     retrieved: 2026-10-19
     raw_sha256: 30bc2b6fa85d27b56d0e267e7b6f8d62a5c3e1a9b2e9481ad0249b4e1cf725a3
     note: text extraction of the original page; formatting simplified -->

BloodHound Community Edition Quickstart - SpecterOps

## Documentation Index

Fetch the complete documentation index at: /llms.txt

Use this file to discover all available pages before exploring further.

Skip to main content

 This quickstart guide walks you through installing BloodHound Community Edition (BloodHound CE) using the BloodHound CLI (BH-CLI), which is a wrapper around Docker Compose. After installation, you’ll learn how to ingest data into BloodHound CE and explore attack paths in your environment.

Are you a blue team member looking to remediate identity risks? Request a demo of BloodHound Enterprise <https://specterops.io/get-a-demo/>.

##
​

Prerequisites
 BloodHound CE deploys in a traditional multi-tier container architecture consisting of database, application, and UI layers. To complete installation, ensure your system meets the following requirements:

Minimum specificationsFor large environments (>50K users)

8GB of RAM96GB of RAM

4 processor cores12 processor cores

10GB hard disk space50GB hard disk space

During startup, BloodHound CE runs initial graph analysis that may continue for about the first minute after launch. On low-memory hosts, sending API requests immediately after container startup can cause the `bloodhound` container to terminate with exit code `137` (out of memory).To avoid this behavior, allocate at least 8GB of RAM or wait for startup processing to complete before running API automation tasks such as user creation.

##
​

Install BloodHound CE

BloodHound Community Edition is a security auditing tool that was written to test the resilience of networks against attackers. Because this tool can equally be used for evil, some anti-malware and endpoint detection and response (EDR) solutions flag BloodHound and its components as malware.If you encounter issues with downloads being blocked and files being prohibited from execution, create targeted allow-list entries for the specific BloodHound binaries, supporting libraries, and installation paths required for your deployment. We recommend that you set up BloodHound on a dedicated machine so that your regular work environment remains protected. If you are planning to use BloodHound on a corporate network, notify your Security Operations Center (SOC) or Chief Information Security Officer (CISO) ahead of time and ensure you have the required permissions to audit the network.For legal and ethical reasons, you must never use BloodHound on systems you do not own or lack explicit permission to audit.

 Installing BloodHound CE with the BloodHound CLI is the easiest way to get started. The CLI handles downloading the necessary Docker images and creating the `docker-compose.yml` file with standard defaults.

1

Install Docker Desktop

For ease and convenience, we recommend installing Docker Desktop <https://www.docker.com/get-started> to run BloodHound CE containers on your local machine.

2

Download BloodHound CLI

Download the latest release of BloodHound CLI <https://github.com/SpecterOps/bloodhound-cli/releases> for your operating system and architecture (AMD or ARM).BloodHound CLI is a utility that makes it easy to install BloodHound CE in containers on your machine.

To avoid the software getting blocked as malware in the browser, we recommend downloading it using the command line.

```
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz

```

```
curl.exe -L -o "$env:USERPROFILE\Downloads\bloodhound-cli-windows-amd64.zip" https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-windows-amd64.zip

```

```
curl -L -o bloodhound-cli-darwin-arm64.tar.gz https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-darwin-arm64.tar.gz

```

3

Unpack the file

Change to the directory where you downloaded the file and unpack it.

```
tar -xvzf bloodhound-cli-linux-amd64.tar.gz

```

```
cd "$env:USERPROFILE\Downloads"; tar -xf bloodhound-cli-windows-amd64.zip

```

```
tar -xvzf bloodhound-cli-darwin-arm64.tar.gz

```

4

Run the install command

In your terminal or PowerShell, navigate to the directory where you unpacked the BloodHound CLI and install BloodHound CE:

```
./bloodhound-cli install

```

```
.\bloodhound-cli install

```

```
./bloodhound-cli install

```

Encountering issues? See troubleshooting.

5

Wait for installation to complete

Keep your terminal open until you see the randomly generated password displayed. Save this password for the next step.

```
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: <Password>

```

If you lose the password, reset it with:

```
./bloodhound-cli resetpwd

```

```
.\bloodhound-cli resetpwd

```

```
./bloodhound-cli resetpwd

```

6

Log in to BloodHound

In a browser, go to http://localhost:8080/ui/login <http://localhost:8080/ui/login> and log in with the `admin` username and the randomly generated password.

The default `docker-compose.yml` file binds only to localhost (127.0.0.1). To access BloodHound outside localhost, follow the instructions in examples/docker-compose/README.md <https://github.com/SpecterOps/BloodHound/blob/main/examples/docker-compose/README.md>.

7

Reset your password

Reset your password as prompted on first login.

##
​

Get data into BloodHound
 To get data into BloodHound, ingest sample data or collect data from your environment with either standalone collectors or OpenHound.

-
 Option 1: Sample data (faster)

-
 Option 2: Data collectors (more realistic)

Use sample data to quickly explore BloodHound CE without setting up a SharpHound or AzureHound data collector.

1

Download sample data

-
 Active Directory

-
 Azure

Download sample data for Active Directory <https://raw.githubusercontent.com/SpecterOps/BloodHound-Docs/main/docs/assets/sample-data/ad_sampledata.zip>.Active Directory sample data generated with SharpHound includes:

- 3 collected domains with trusts between them

- Additional, visible, trusted domains without collections

- Coverage for local permissions

- Multiple ADCS escalation paths

Download sample data for Azure <https://raw.githubusercontent.com/SpecterOps/BloodHound-Docs/main/docs/assets/sample-data/entra_sampledata.zip>.Azure sample data generated with AzureHound includes:

- Full collection of an Azure environment

- Support for user-sync hybrid paths when ingested alongside the example AD data

2

Upload sample data to BloodHound CE

- Log in to the BloodHound CE UI.

- In the left menu, click  Quick Upload

- Click the Upload Files modal to open a file system dialog or drag and drop the downloaded sample data ZIP file.

- Click Upload to begin the data ingest process.

The default admin email is `admin@example.com` and will appear as the user ingesting the data.

There are two main ways to collect data for BloodHound CE:

- Active Directory, collected by SharpHound CE

- Entra ID (formerly Azure AD) and Azure IaaS, collected by AzureHound CE

- Github, Jamf, and Okta, collected by OpenHound CLI for BloodHound CE

Use OpenHound for built-in collectors and workflows for platforms like GitHub, Jamf, and Okta. For additional community-built collectors, explore the OpenGraph Library.

1

Choose a collection method

Pick the collection method that best fits your environment:

- Use SharpHound CE for Active Directory and AzureHound CE for Entra ID.

- Use OpenHound CLI for supported SaaS and platform data sources, such as Github, Jamf, and Okta.

2

Download a collector

Each collector is a standalone binary. You can download SharpHound CE and AzureHound CE using one of the following methods:

To install the OpenHound CLI and configure supported collectors, see OpenHound Community.

-
 BloodHound CE UI

-
 GitHub

-
 Source

Download the collectors directly from the BloodHound CE UI:

- Log in to the BloodHound CE UI.

- In the left menu, click Download Collectors.

- Click one of the links in the Community Collectors section to download the SharpHound or AzureHound binary.

Download the latest releases from GitHub:

- SharpHound releases <https://github.com/SpecterOps/SharpHound/releases/latest>

- AzureHound releases <https://github.com/SpecterOps/AzureHound/releases/latest>

Build the collector from the data collector source code

- SharpHound

- AzureHound

3

Run a collector

Start the collector to generate and compress JSON files into a ZIP archive.

```
# Run SharpHound CE from a domain-joined Windows system
C:\> SharpHound.exe

```

```
# Provide your credentials and tenant information to run AzureHound CE
C:\> AzureHound.exe --username "MattNelson@contoso.onmicrosoft.com" --password "MyVeryStrongPassword" --tenant "contoso.onmicrosoft.com" list

```

```
# Collect data with OpenHound CLI for BloodHound CE
openhound collect okta ./output

# Convert collected data to OpenGraph format for BloodHound CE
openhound convert okta ./output/okta ./graph/okta

```

For command options, see:

- SharpHound Community Edition Flags

- AzureHound Community Edition Flags

- OpenHound CLI

4

Ingest data into BloodHound

Use the BloodHound CE API or the BloodHound CE UI to ingest collected data into BloodHound.To ingest collected data with the API, use the BloodHound CE endpoint `/api/v2/file-upload/`. See the BloodHound API documentation for details.To ingest collected data with the BloodHound CE UI, go to Administration > Data Collection > File Ingest and click Upload File(s) to upload your files.

BloodHound CE accepts .zip archives or JSON files, with no size limit. Your browser’s ability to package the uploaded file is a limiting factor in uploading large datasets directly through the UI.

##
​

Explore attack paths
 To look at identified attack paths in the graph, go to the Explore page in the BloodHound CE UI.

1

Search for a user

-  In the Search bar, search nodes for a user object.

-  For Active Directory sample data, enter `user:bob`.

-  For Azure sample data, enter `azuser:bob`.

-  Select the user and click on the node that appears.

-  Explore information about the user’s sessions and memberships.

2

Pathfind

Review the path from one user to another on the Pathfinding tab. For example, pathfind from `BOB@PHANTOM.CORP` to `ADMINISTRATORS@PHANTOM.CORP`.To route through additional objects, select Add Destination and enter up to two more destination nodes in the order you want BloodHound to traverse them.

3

Explore Cypher queries

Explore the pre-saved Cypher queries on the Cypher tab.

Learn more in Explore → Search for Objects.

##
​

Update BloodHound CE
 The easiest way to update your instance of BloodHound Community Edition is via `bloodhound-cli`.

```
./bloodhound-cli update

```

```
.\bloodhound-cli update

```

```
./bloodhound-cli update

```

##
​

Next steps

- Learn how to work with the BloodHound API

- Configure BloodHound integrations

##
​

Troubleshooting
 If you encounter issues during installation, refer to the following common problems and solutions.

"bloodhound-cli" Not Opened - Apple security check

When running `./bloodhound-cli install`, you may see an error stating that Apple could not verify the binary is free of malware. This is a standard macOS security check for unsigned or unnotarized applications.Terminal (Quick Fix)

- Clear the quarantine flag by running:

```
xattr -d com.apple.quarantine ./bloodhound-cli

```

- Repeat the CLI command: `./bloodhound-cli install`

System Settings (GUI)

- Go to System Settings (or System Preferences on older macOS versions)

- Navigate to Privacy & Security

- Scroll down to the Security section

- You should see a message stating that bloodhound-cli was blocked

- Click Allow Anyway

- Repeat the CLI command: `./bloodhound-cli install`

- Click Open Anyway when prompted

- Enter your password or use your fingerprint to confirm

Malware Blocked - "com.docker.vmnetd" contains malware

This error occurs when macOS blocks Docker’s networking component. Resolve it by reinstalling Docker:

- Follow the Docker uninstall instructions <https://docs.docker.com/desktop/uninstall/> (select your operating system tab)

- Re-install Docker Desktop <https://www.docker.com/get-started/>

- Repeat the CLI command: `./bloodhound-cli install`

Docker daemon is not running

If you see an error stating “Docker is installed on this system, but the daemon is not running”:

- Simply launch Docker Desktop from your Applications folder

- Wait for Docker to fully start

- Repeat the CLI command: `./bloodhound-cli install`

Suggest edits <https://github.com/specterops/bloodhound-docs/edit/main/docs/get-started/quickstart/community-edition-quickstart.mdx>Raise issue <https://github.com/specterops/bloodhound-docs/issues/new?title=Issue on docs&body=Path: /get-started/quickstart/community-edition-quickstart>