<!-- source: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
     fetched_from: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
     retrieved: 2026-10-19
     raw_sha256: 1a7a847aa13e45a07daa03af6a9a47b7fecac77db968d04b9daacf35eadd03ce
     note: text extraction of the original page; formatting simplified -->

Configuration and credential file settings in the AWS CLI - AWS Command Line Interface

View a markdown version of this page

Configuration and credential file settings in the AWS CLI - AWS Command Line Interface

DocumentationAWS Command Line InterfaceUser Guide for Version 2

Format of the configuration and credential filesWhere are configuration settings stored?Using named profilesSet and view configuration settings using commandsSetting new configuration and credentials command examplesSupported config file settings

# Configuration and credential file settings in the AWS CLI

You can save your frequently used configuration settings and credentials in files that are maintained by the AWS CLI.

The files are divided into `profiles`. By default, the AWS CLI uses the settings found in the profile named `default`. To use alternate settings, you can create and reference additional profiles.

You can override an individual setting by either setting one of the supported environment variables, or by using a command line parameter. For more information on configuration setting precedence, see Configuring settings for the AWS CLI.

###### Note

For information on setting up your credentials, see Authentication and access credentials for the AWS CLI.

###### Topics

-
Format of the configuration and credential files

-
Where are configuration settings stored?

-
Using named profiles

-
Set and view configuration settings using commands

-
Setting new configuration and credentials command examples

-
Supported config file settings

## Format of the configuration and credential files

The `config` and `credentials` files are organized into sections. Sections include profiles, sso-sessions, and services. A section is a named collection of settings, and continues until another section definition line is encountered. Multiple profiles and sections can be stored in the `config` and `credentials` files.

These files are plaintext files that use the following format:

-
Section names are enclosed in brackets [ ] such as `[default]`, `[profile `user1`]`, and `[sso-session]`.

-
All entries in a section take the general form of `setting_name=value`.

-
Lines can be commented out by starting the line with a hash character (`#`).

###### The config and credentials files contain the following section types:

-
profile

-
sso-session

-
services

### Section type: `profile`

Depending on the file, profile section names use the following format:

-
Config file: `[default]` `[profile `user1`]`

-
Credentials file: `[default]` `[`user1`]`

Do not use the word `profile` when creating an entry in the `credentials` file.

Each profile can specify different credentials and can also specify different AWS Regions and output formats. When naming the profile in a `config` file, include the prefix word "`profile`", but do not include it in the `credentials` file.

The following examples show a `credentials` and `config` file with two profiles, region, and output specified. The first [default] is used when you run a AWS CLI command with no profile specified. The second is used when you run a AWS CLI command with the `--profile user1` parameter.
  IAM Identity Center (SSO)
This example is for AWS IAM Identity Center. For more information, see Configuring IAM Identity Center authentication with the AWS CLI.

Credentials file

The `credentials` file is not used for this authentication method.

Config file

```

[default]
sso_session = my-sso
sso_account_id = 111122223333
sso_role_name = readOnly
region = us-west-2
output = text

[profile user1]
sso_session = my-sso
sso_account_id = 444455556666
sso_role_name = readOnly
region = us-east-1
output = json

[sso-session my-sso]
sso_region = us-east-1
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_registration_scopes = sso:account:access
```
  IAM Identity Center (Legacy SSO)
This example is for the legacy method of AWS IAM Identity Center. For more information, see Configuring IAM Identity Center authentication with the AWS CLI.

Credentials file

The `credentials` file is not used for this authentication method.

Config file

```

[default]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 111122223333
sso_role_name = readOnly
region = us-west-2
output = text

[profile user1]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 444455556666
sso_role_name = readOnly
region = us-east-1
output = json
```
  Short-term credentials
This example is for the short-term credentials from AWS Identity and Access Management. For more information, see Authenticating with short-term credentials for the AWS CLI.

Credentials file

```

[default]
aws_access_key_id=ASIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE

[user1]
aws_access_key_id=ASIAI44QH8DHBEXAMPLE
aws_secret_access_key=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token = fcZib3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE
```

Config file

```

[default]
region=us-west-2
output=json

[profile user1]
region=us-east-1
output=text
```
  IAM role
This example is for assuming an IAM role. Profiles that use IAM roles pull credentials from another profile, and then apply IAM role permissions. In the following examples, `default` is the source profile for credentials and `user1` borrows the same credentials then assumes a new role. For more information, see Using an IAM role in the AWS CLI.

Credentials file

The `credentials` file depends on what authentication your source profile uses. For the following example, the source profile uses short-term credentials.

```

[default]
aws_access_key_id=ASIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE
```

Config file

```

[default]
region=us-west-2
output=json

[profile user1]
role_arn=arn:aws:iam::777788889999:role/user1role
source_profile=default
role_session_name=session_user1
region=us-east-1
output=text
```
  Amazon EC2 instance metadata credentials
This example is for the credentials obtained from the hosting Amazon EC2 instance metadata. For more information, see Using Amazon EC2 instance metadata as credentials in the AWS CLI.

Credentials file

The `credentials` file is not used for this authentication method.

Config file

```

[default]
role_arn=arn:aws:iam::123456789012:role/defaultrole
credential_source=Ec2InstanceMetadata
region=us-west-2
output=json

[profile user1]
role_arn=arn:aws:iam::777788889999:role/user1role
credential_source=Ec2InstanceMetadata
region=us-east-1
output=text
```
  Long-term credentials

###### Warning

To avoid security risks, don't use IAM users for authentication when developing purpose-built software or working with real data. Instead, use federation with an identity provider such as AWS IAM Identity Center <https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html>.

This example is for the long-term credentials from AWS Identity and Access Management. For more information, see Authenticating using IAM user credentials for the AWS CLI.

Credentials file

```

[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[user1]
aws_access_key_id=AKIAI44QH8DHBEXAMPLE
aws_secret_access_key=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
```

Config file

```

[default]
region=us-west-2
output=json

[profile user1]
region=us-east-1
output=text
```

For more information and additional authorization and credential methods see, see Authenticating using IAM user credentials for the AWS CLI.

### Section type: `sso-session`

The `sso-session` section of the `config` file is used to group configuration variables for acquiring SSO access tokens, which can then be used to acquire AWS credentials. The following settings are used:

-
(Required) `sso_start_url`

-
(Required) `sso_region`

-
`sso_account_id`

-
`sso_role_name`

-
`sso_registration_scopes`

You define an `sso-session` section and associate it to a profile. `sso_region` and `sso_start_url` must be set within the `sso-session` section. Typically, `sso_account_id` and `sso_role_name` must be set in the `profile` section so that the SDK can request SSO credentials.

The following example configures the SDK to request SSO credentials and supports automated token refresh:

```

[profile dev]
sso_session = my-sso
sso_account_id = 111122223333
sso_role_name = SampleRole

[sso-session my-sso]
sso_region = us-east-1
sso_start_url = https://my-sso-portal.awsapps.com/start
```

This also allows `sso-session` configurations to be reused across multiple profiles:

```

[profile dev]
sso_session = my-sso
sso_account_id = 111122223333
sso_role_name = SampleRole

[profile prod]
sso_session = my-sso
sso_account_id = 111122223333
sso_role_name = SampleRole2

[sso-session my-sso]
sso_region = us-east-1
sso_start_url = https://my-sso-portal.awsapps.com/start
```

However, `sso_account_id` and `sso_role_name` aren't required for all scenarios of SSO token configuration. If your application only uses AWS services that support bearer authentication, then traditional AWS credentials are not needed. Bearer authentication is an HTTP authentication scheme that uses security tokens called bearer tokens. In this scenario, `sso_account_id` and `sso_role_name` aren't required. See the individual guide for your AWS service to determine if it supports bearer token authorization.

Additionally, registration scopes can be configured as part of a `sso-session`. Scope is a mechanism in OAuth 2.0 to limit an application's access to a user's account. An application can request one or more scopes, and the access token issued to the application will be limited to the scopes granted. These scopes define the permissions requested to be authorized for the registered OIDC client and access tokens retrieved by the client. The following example sets `sso_registration_scopes` to provide access for listing accounts/roles:

```

[sso-session my-sso]
sso_region = us-east-1
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_registration_scopes = sso:account:access
```

The authentication token is cached to disk under the `~/.aws/sso/cache` directory with a filename based on the session name.

For more information on this configuration type, see Configuring IAM Identity Center authentication with the AWS CLI.

### Section type: `services`

The `services` section is a group of settings that configures custom endpoints for AWS service requests. A profile then is linked to a `services` section.

```

[profile dev]
services = my-services
```

The `services` section is separated into subsections by `<SERVICE> = ` lines, where `<SERVICE>` is the AWS service identifier key. The AWS service identifier is based on the API model’s `serviceId` by replacing all spaces with underscores and lowercasing all letters. For a list of all service identifier keys to use in the `services` section, see Using endpoints in the AWS CLI. The service identifier key is followed by nested settings with each on its own line and indented by two spaces.

The following example configures the endpoint to use for requests made to the Amazon DynamoDB service in the `my-services` section that is used in the `dev` profile. Any immediately following lines that are indented are included in that subsection and apply to that service.

```

[profile dev]
services = my-services

[services my-services]
dynamodb =
  endpoint_url = http://localhost:8000
```

For more information on service-specific endpoints, see Using endpoints in the AWS CLI.

If your profile has role-based credentials configured through a `source_profile` parameter for IAM assume role functionality, the SDK only uses service configurations for the specified profile. It does not use profiles that are role chained to it. For example, using the following shared `config` file:

```

[profile A]
credential_source = Ec2InstanceMetadata
endpoint_url = https://profile-a-endpoint.aws/

[profile B]
source_profile = A
role_arn = arn:aws:iam::123456789012:role/roleB
services = profileB

[services profileB]
ec2 =
  endpoint_url = https://profile-b-ec2-endpoint.aws
```

 If you use profile `B` and make a call in your code to Amazon EC2, the endpoint resolves as `https://profile-b-ec2-endpoint.aws`. If your code makes a request to any other service, the endpoint resolution will not follow any custom logic. The endpoint does not resolve to the global endpoint defined in profile `A`. For a global endpoint to take effect for profile `B`, you would need to set `endpoint_url` directly within profile `B`.

## Where are configuration settings stored?

The AWS CLI stores sensitive credential information that you specify with `aws configure` in a local file named `credentials`, in a folder named ``.aws`` in your home directory. The less sensitive configuration options that you specify with `aws configure` are stored in a local file named `config`, also stored in the ``.aws`` folder in your home directory.

###### Storing credentials in the config file

You can keep all of your profile settings in a single file as the AWS CLI can read credentials from the `config` file. If there are credentials in both files for a profile sharing the same name, the keys in the credentials file take precedence. We suggest keeping credentials in the `credentials` files. These files are also used by the various language software development kits (SDKs). If you use one of the SDKs in addition to the AWS CLI, confirm if the credentials should be stored in their own file.

Where you find your home directory location varies based on the operating system, but is referred to using the environment variables `%UserProfile%` in Windows and `$HOME` or `~` (tilde) in Unix-based systems. You can specify a non-default location for the files by setting the `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` environment variables to another local path. See Configuring environment variables for the AWS CLI for details.

When you use a shared profile that specifies an AWS Identity and Access Management (IAM) role, the AWS CLI calls the AWS STS `AssumeRole` operation to retrieve temporary credentials. These credentials are then stored (in ``~/.aws/cli/cache``). Subsequent AWS CLI commands use the cached temporary credentials until they expire, and at that point the AWS CLI automatically refreshes the credentials.

## Using named profiles

If no profile is explicitly defined, the `default` profile is used.

To use a named profile, add the `--profile `profile-name`` option to your command. The following example lists all of your Amazon EC2 instances using the credentials and settings defined in the `user1` profile.

```

$ aws ec2 describe-instances --profile user1
```

To use a named profile for multiple commands, you can avoid specifying the profile in every command by setting the `AWS_PROFILE` environment variable as the default profile. You can override this setting by using the `--profile` parameter.
  Linux or macOS

```

$ export AWS_PROFILE=user1
```
  Windows

```

C:\> setx AWS_PROFILE user1
```

Using `set <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/set_1>` to set an environment variable changes the value used until the end of the current command prompt session, or until you set the variable to a different value.

Using `setx` <https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/setx> to set an environment variable changes the value in all command shells that you create after running the command. It does not affect any command shell that is already running at the time you run the command. Close and restart the command shell to see the effects of the change.

Setting the environment variable changes the default profile until the end of your shell session, or until you set the variable to a different value. You can make environment variables persistent across future sessions by putting them in your shell's startup script. For more information, see Configuring environment variables for the AWS CLI.

## Set and view configuration settings using commands

There are several ways to view and set your configuration settings using commands.

  `aws configure <https://docs.aws.amazon.com/cli/v1/reference/configure/index.html>`
Run this command to quickly set and view your credentials, Region, and output format. The following example shows sample values.

```

$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```
  `aws configure set <https://docs.aws.amazon.com/cli/v1/reference/configure/set.html>`
You can set any credentials or configuration settings using `aws configure set`. Specify the profile that you want to view or modify with the `--profile` setting.

For example, the following command sets the `region` in the profile named `integ`.

```

$ aws configure set region us-west-2 --profile integ
```

To remove a setting, manually delete the setting in your `config` and `credentials` files in a text editor.
  `aws configure get` <https://docs.aws.amazon.com/cli/v1/reference/configure/get.html>
You can retrieve any credentials or configuration settings you've set using `aws configure get`. Specify the profile that you want to view or modify with the `--profile` setting.

For example, the following command retrieves the `region` setting in the profile named `integ`.

```

$ aws configure get region --profile integ
us-west-2
```

If the output is empty, the setting is not explicitly set and uses the default value.

`aws configure import` <https://docs.aws.amazon.com/cli/latest/reference/reference/configure/import.html>
Import `CSV` credentials generated from the IAM web console. This is not for credentials generated from IAM Identity Center; customers who use IAM Identity Center should use aws configure sso. A CSV file is imported with the profile name matching the username. The CSV file must contain the following headers.

-
User Name

-
Access key ID

-
Secret access key

###### Note

During initial key pair creation, once you close the Download .csv file dialog box, you cannot access your secret access key after you close the dialog box. If you need a `.csv` file, you'll need to create one yourself with the required headers and your stored key pair information. If you do not have access to your key pair information, you need to create a new key pair.

```

$ aws configure import --csv file://credentials.csv
```
  `aws configure list` <https://docs.aws.amazon.com/cli/v1/reference/configure/list.html>
To list configuration data, use the `aws configure list` command. This command lists the profile, access key, secret key, and region configuration information used for the specified profile. For each configuration item, it shows the value, where the configuration value was retrieved, and the configuration variable name.

For example, if you provide the AWS Region in an environment variable, this command shows you the name of the region you've configured, that this value came from an environment variable, and the name of the environment variable.

For temporary credential methods such as roles and IAM Identity Center, this command displays the temporarily cached access key and secret access key is displayed.

```

$ aws configure list
NAME       : VALUE                : TYPE                    : LOCATION
profile    : <not set>            : None                    : None
access_key : ****************ABCD : shared-credentials-file :
secret_key : ****************ABCD : shared-credentials-file :
region     : us-west-2            : env                     : AWS_DEFAULT_REGION
```
  `aws configure list-profiles` <https://docs.aws.amazon.com/cli/v1/reference/configure/list-profiles.html>
To list all your profile names, use the `aws configure list-profiles` command.

```

$ aws configure list-profiles
default
test
```
  `aws configure mfa-login`
Run this command to configure a new profile to use with multi-factor authentication (MFA) and your IAM user credentials in the specified profile. If no profile is specified, the MFA is based on the `default` profile. If no default profile is configured, the `mfa-login` command prompts you for you AWS credentials before asking for your MFA information. The following command example uses your default configuration and creates an MFA profile.

```

$ aws configure mfa-login
MFA serial number or ARN: arn:aws:iam::123456789012:mfa/MFADeviceName
MFA token code: 123456
Profile to update [session-MFADeviceName]:
Temporary credentials written to profile 'session-MFADeviceName'
Credentials will expire at 2023-05-19 18:06:10 UTC
To use these credentials, specify --profile session-MFADeviceName when running AWS CLI commands
```

To update an existing profile, use the `--update-profile` parameter.

```

$ aws configure mfa-login --profile myprofile --update-profile mfaprofile
MFA token code: 123456
Temporary credentials written to profile 'mfaprofile'
Credentials will expire at 2023-05-19 18:06:10 UTC
To use these credentials, specify --profile mfaprofile when running AWS CLI commands
```

This command currently supports only hardware or software based one-time password (OTP) authenticators. Passkeys and U2F devices are not currently supported with this command.

For more information on using MFA with IAM, see AWS Multi-factor authentication in IAM  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html> in the AWS Identity and Access Management User Guide.
  `aws configure sso`
Run this command to quickly set and view your AWS IAM Identity Center credentials, Region, and output format. The following example shows sample values.

```

$ aws configure sso
SSO session name (Recommended): my-sso
SSO start URL [None]: https://my-sso-portal.awsapps.com/start
SSO region [None]: us-east-1
SSO registration scopes [None]: sso:account:access
```
  `aws configure sso-session`
Run this command to quickly set and view your AWS IAM Identity Center credentials, Region, and output format in the `sso-session` section of the `credentials` and `config` files. The following example shows sample values.

```

$ aws configure sso-session
SSO session name: my-sso
SSO start URL [None]: https://my-sso-portal.awsapps.com/start
SSO region [None]: us-east-1
SSO registration scopes [None]: sso:account:access
```
  `

aws configure export-credentials`
Run this command to export currently set credentials in the specified format. By default, the command exports the default credentials in the `process` format, which is a JSON format supported by the AWS SDKs and Tools credential format.

```

$ aws configure export-credentials
{
  "Version": 1,
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

To export a specific profile and format, use the `--profile` and `--format` options. The format options are as follows:

-
(default)`process` ‐ The JSON format supported by the AWS SDKs and Tools `credential_process` configuration.

-
`env` ‐ Environment variables in exported shell format.

-
`env-no-export` ‐ Non-exported environment variables in shell format.

-
`powershell` ‐ Environment variables in PowerShell format.

-
`windows-cmd` ‐ Environment variables in Windows Command Line format.

The following example exports the `user1` profile to an exported shell format.

```

$ aws configure export-credentials --profile user1 --format env
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

## Setting new configuration and credentials command examples

The following examples show configuring a default profile with credentials, region, and output specified for different authentication methods.
  Console sessions as short-term credentials
This example lets you use your existing console credentials with the `aws login` command. This sign in method can be used with root credentials created during initial account set up, an IAM user, or a federated identity from your identity provider. For more information, see Login for AWS local development using console credentials <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html>.

```

$ aws login
No AWS region has been configured. The AWS region is the geographic location of your AWS resources.

If you've used AWS before and already have resources in your account, tell us which region they were
created in. If you haven't created resources in your account before, you can pick the region closest to you:
https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html. You are able to change
the region in the CLI at any time with the command `aws configure set region NEW_REGION`.

AWS Region [us-east-1]: us-east-1
Attempting to open the login page for `us-east-1` in your default browser. If the browser does not open,
use the following URL to complete your login:

https://us-east-1.signin.aws.amazon.com/v1/authorize<abbreviated>

If you cannot connect to this URL, make sure that you have specified a valid region.

Waiting for login...

Logged in with role `arn:aws:sts::012345678910:user/iam-user`, and configured profile
`default` to use `us-east-1`. This session will expire on October 14, 2025 at 2:04 PST. After this time, you
can renew your session with `aws login`.
```
  IAM Identity Center (SSO)
This example is for AWS IAM Identity Center using the `aws configure sso` wizard. For more information, see Configuring IAM Identity Center authentication with the AWS CLI.

```

$ aws configure sso
SSO session name (Recommended): my-sso
SSO start URL [None]: https://my-sso-portal.awsapps.com/start
SSO region [None]:us-east-1

Attempting to automatically open the SSO authorization page in your default browser.

There are 2 AWS accounts available to you.
> DeveloperAccount, developer-account-admin@example.com (111122223333)
  ProductionAccount, production-account-admin@example.com (444455556666)

Using the account ID 111122223333

There are 2 roles available to you.
> ReadOnly
  FullAccess

Using the role name "ReadOnly"

CLI default client Region [None]: us-west-2
CLI default output format [None]: json
CLI profile name [123456789011_ReadOnly]: user1
```
  IAM Identity Center (Legacy SSO)
This example is for the legacy method of AWS IAM Identity Center using the `aws configure sso` wizard. To use the legacy SSO, leave the session name blank. For more information, see Configuring IAM Identity Center authentication with the AWS CLI.

```

$ aws configure sso
SSO session name (Recommended):
SSO start URL [None]: https://my-sso-portal.awsapps.com/start
SSO region [None]:us-east-1

SSO authorization page has automatically been opened in your default browser.
Follow the instructions in the browser to complete this authorization request.

There are 2 AWS accounts available to you.
> DeveloperAccount, developer-account-admin@example.com (111122223333)
  ProductionAccount, production-account-admin@example.com (444455556666)

Using the account ID 111122223333

There are 2 roles available to you.
> ReadOnly
  FullAccess

Using the role name "ReadOnly"

CLI default client Region [None]: us-west-2
CLI default output format [None]: json
CLI profile name [123456789011_ReadOnly]: user1
```
  Short-term credentials
This example is for the short-term credentials from AWS Identity and Access Management. The aws configure wizard is used to set initial values and then the `aws configure set` command assigns the last value needed. For more information, see Authenticating with short-term credentials for the AWS CLI.

```

$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
$ aws configure set aws_session_token fcZib3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZ2luX2IQoJb3JpZVERYLONGSTRINGEXAMPLE
```
  IAM role
This example is for assuming an IAM role. Profiles that use IAM roles pull credentials from another profile, and then apply IAM role permissions. In the following examples, `default` is the source profile for credentials and `user1` borrows the same credentials then assumes a new role. There is no wizard for this process, therefore each value is set using the `aws configure set` command. For more information, see Using an IAM role in the AWS CLI.

```

$ aws configure set role_arn arn:aws:iam::123456789012:role/defaultrole
$ aws configure set source_profile default
$ aws configure set role_session_name session_user1
$ aws configure set region us-west-2
$ aws configure set output json
```
  Amazon EC2 instance metadata credentials
This example is for the credentials obtained from the hosting Amazon EC2 instance metadata. There is no wizard for this process, therefore each value is set using the `aws configure set` command. For more information, see Using Amazon EC2 instance metadata as credentials in the AWS CLI.

```

$ aws configure set role_arn arn:aws:iam::123456789012:role/defaultrole
$ aws configure set credential_source Ec2InstanceMetadata
$ aws configure set region us-west-2
$ aws configure set output json
```
  Long-term credentials

###### Warning

To avoid security risks, don't use IAM users for authentication when developing purpose-built software or working with real data. Instead, use federation with an identity provider such as AWS IAM Identity Center <https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html>.

This example is for the long-term credentials from AWS Identity and Access Management. For more information, see Authenticating using IAM user credentials for the AWS CLI.

```

$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

## Supported `config` file settings

###### Topics

-
Global settings

-
S3 Custom command settings

The following settings are supported in the `config` file. The values listed in the specified (or default) profile are used unless they are overridden by the presence of an environment variable with the same name, or a command line option with the same name. For more information on what order settings take precendence, see Configuring settings for the AWS CLI

### Global settings

 `account_id_endpoint_mode`
Specifies whether to use AWS account-based endpoint IDs for calls to supported AWS services. For more information on account-based endpoints, see Account-based endpoints.

This setting can be set to the following:

-
(default) `preferred` – The endpoint should include account ID if available.

-
`disabled` – A resolved endpoint doesn't include account ID.

-
`required` – The endpoint must include account ID. If the account ID isn't available, the SDK throws an error.

Can be overridden by the `AWS_ACCOUNT_ID_ENDPOINT_MODE` environment variable. To use account-based endpoints, the ID must be set in the `AWS_ACCOUNT_ID` environment variable or `aws_account_id` setting.

```

account_id_endpoint_mode = preferred
```

###### Endpoint precedence

Endpoint configuration settings are located in multiple places, such as the system or user environment variables, local AWS configuration files, or explicitly declared on the command line as a parameter. The AWS CLI checks these endpoint settings in a particular order, and uses the endpoint setting with the highest precedence. For the endpoint precedence list, see Endpoint configuration and settings precedence.

 `aws_access_key_id`
Specifies the AWS access key used as part of the credentials to authenticate the command request. Although this can be stored in the `config` file, we recommend that you store this in the `credentials` file.

Can be overridden by the `AWS_ACCESS_KEY_ID` environment variable. You can't specify the access key ID as a command line option.

```

aws_access_key_id = AKIAIOSFODNN7EXAMPLE
```

 `aws_account_id`
Specifies the AWS account-based endpoint ID to use for calls to supported AWS services. For more information on account-based endpoints, see Account-based endpoints.

Can be overridden by the `AWS_ACCOUNT_ID` environment variable. The `AWS_ACCOUNT_ID_ENDPOINT_MODE` environment variable or `account_id_endpoint_mode` setting must be set to `preferred` or `required` to use this setting.

```

aws_account_id = 123456789EXAMPLE
```

###### Endpoint precedence

Endpoint configuration settings are located in multiple places, such as the system or user environment variables, local AWS configuration files, or explicitly declared on the command line as a parameter. The AWS CLI checks these endpoint settings in a particular order, and uses the endpoint setting with the highest precedence. For the endpoint precedence list, see Endpoint configuration and settings precedence.

`aws_secret_access_key`
Specifies the AWS secret key used as part of the credentials to authenticate the command request. Although this can be stored in the `config` file, we recommend that you store this in the `credentials` file.

Can be overridden by the `AWS_SECRET_ACCESS_KEY` environment variable. You can't specify the secret access key as a command line option.

```

aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

`aws_session_token`
Specifies an AWS session token. A session token is required only if you manually specify temporary security credentials. Although this can be stored in the `config` file, we recommend that you store this in the `credentials` file.

Can be overridden by the `AWS_SESSION_TOKEN` environment variable. You can't specify the session token as a command line option.

```

aws_session_token = AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4Olgk
```

`ca_bundle`
Specifies a CA certificate bundle (a file with the `.pem` extension) that is used to verify SSL certificates.

Can be overridden by the `AWS_CA_BUNDLE` environment variable or the `--ca-bundle` command line option.

```

ca_bundle = dev/apps/ca-certs/cabundle-2019mar05.pem
```

`cli_auto_prompt`
Enables the auto-prompt for the AWS CLI version 2. There are two settings that can be used:

-
`on` uses the full auto-prompt mode each time you attempt to run an `aws` command. This includes pressing ENTER after both a complete command or incomplete command.

```

cli_auto_prompt = on
```

-
`on-partial` uses partial auto-prompt mode. If a command is incomplete or cannot be run due to client-side validation errors, auto-prompt is used. This mode is particular useful if you have pre-existing scripts, runbooks, or you only want to be auto-prompted for commands you are unfamiliar with rather than prompted on every command.

```

cli_auto_prompt = on-partial
```

You can override this setting by using the `aws_cli_auto_prompt` environment variable or the `--cli-auto-prompt` and `--no-cli-auto-prompt` command line parameters.

For information on the AWS CLI version 2 auto-prompt feature, see Enabling and using command prompts in the AWS CLI.

`cli_binary_format`
Specifies how the AWS CLI version 2 interprets binary input parameters. It can be one of the following values:

-
base64 – This is the default value. An input parameter that is typed as a binary large object (BLOB) accepts a base64-encoded string. To pass true binary content, put the content in a file and provide the file's path and name with the `fileb://` prefix as the parameter's value. To pass base64-encoded text contained in a file, provide the file's path and name with the `file://` prefix as the parameter's value.

-
raw-in-base64-out – Default for the AWS CLI version 1. If the setting's value is `raw-in-base64-out`, files referenced using the `file://` prefix is read as text and then the AWS CLI attempts to encode it to binary.

This entry does not have an equivalent environment variable. You can specify the value on a single command by using the `--cli-binary-format raw-in-base64-out` parameter.

```

cli_binary_format = raw-in-base64-out
```

If you reference a binary value in a file using the `fileb://` prefix notation, the AWS CLI always expects the file to contain raw binary content and does not attempt to convert the value.

If you reference a binary value in a file using the `file://` prefix notation, the AWS CLI handles the file according to the current `cli_binary_format` setting. If that setting's value is `base64` (the default when not explicitly set), the AWS CLI expects the file to contain base64-encoded text. If that setting's value is `raw-in-base64-out`, the AWS CLI expects the file to contain raw binary content.

`cli_help_output`
As of version `2.31.0` The display for the `help` command is configured by the `cli_help_output` setting, and has the following values:

-
 (default) `terminal` ‐ Open the man page in the terminal.

-
`browser` ‐ Open the man page as a local HTML file in your default browser. A notice is printed to your terminal when your default browser is being opened, and an error message if the AWS CLI cannot open your browser.

-
`url` ‐ Print the URL to the online AWS CLI Reference Guide for the version of the AWS CLI you have installed. Settings for client-side paging, such as the `AWS_PAGER` environment variable, is respected.

```

cli_help_output = browser
```

For more information on the `help` command, see Accessing help and resources for the AWS CLI.

`cli_history`
Disabled by default. This setting enables command history for the AWS CLI. After enabling this setting, the AWS CLI records the history of `aws` commands.

```

cli_history = enabled
```

You can list your history using the `aws history list` command, and use the resulting `command_ids` in the `aws history show` command for details. For more information see `aws history` <https://docs.aws.amazon.com/cli/latest/reference/history/index.html> in the AWS CLI reference guide.

`cli_pager`
Specifies the pager program used for output. By default, AWS CLI version 2 returns all output through your operating system’s default pager program.

Can be overridden by the AWS_PAGER environment variable.

```

cli_pager=less
```

`cli_timestamp_format`
Specifies the output format of timestamp values. You can specify either of the following values:

-
iso8601 – The default value for the AWS CLI version 2. If specified, the AWS CLI reformats all timestamps in the output according to ISO 8601 <https://www.iso.org/iso-8601-date-and-time-format.html>. ISO 8601 formatted timestamps look like the following examples. The following example demonstrates how the time is formatted by separating the date and time with a `T` and including a `Z` after the time.

```

YYYY-MM-DDThh:mm:ssZ
```

The following examples shows a timestamp using the previous formatting.

```

2024-05-08T15:16:43Z
```

-
wire – The default value for the AWS CLI version 1. If specified, the AWS CLI displays all timestamp values exactly as received in the HTTP query response.

This setting does not have an equivalent environment variable or command line option. This setting does not alter timestamp inputs, only output formatting.

```

cli_timestamp_format = iso8601
```

`credential_process`
Specifies an external command that the AWS CLI runs to generate or retrieve authentication credentials to use for this command. The command must return the credentials in a specific format. For more information about how to use this setting, see Sourcing credentials with an external process in the AWS CLI.

This entry does not have an equivalent environment variable or command line option.

```

credential_process = /opt/bin/awscreds-retriever --username susan
```

`credential_source`
Used within Amazon EC2 instances or containers to specify where the AWS CLI can find credentials to use to assume the role you specified with the `role_arn` parameter. You cannot specify both `source_profile` and `credential_source` in the same profile.

This parameter can have one of three values:

-
Environment – Specifies that the AWS CLI is to retrieve source credentials from environment variables.

-
Ec2InstanceMetadata – Specifies that the AWS CLI is to use the IAM role attached to the EC2 instance profile <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html> to get source credentials.

-
EcsContainer – Specifies that the AWS CLI is to use the IAM role attached to the ECS container as source credentials.

```

credential_source = Ec2InstanceMetadata
```

`duration_seconds`
Specifies the maximum duration of the role session, in seconds. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role (which can be a maximum of 43200). This is an optional parameter and by default, the value is set to 3600 seconds.

`endpoint_url`
Specifies the endpoint that is used for all service requests. If this setting is used in the services section of the `config` file, then the endpoint is used only for the specified service. For more information, see Set global endpoint for all AWS services.

The following example uses the global endpoint `http://localhost:1234` and a service-specific endpoint of `http://localhost:4567` for Amazon S3.

```

[profile dev]
endpoint_url = http://localhost:1234
services = s3-specific

[services s3-specific]
s3 =
  endpoint_url = http://localhost:4567
```

###### Endpoint precedence

Endpoint configuration settings are located in multiple places, such as the system or user environment variables, local AWS configuration files, or explicitly declared on the command line as a parameter. The AWS CLI checks these endpoint settings in a particular order, and uses the endpoint setting with the highest precedence. For the endpoint precedence list, see Endpoint configuration and settings precedence.

`ignore_configure_endpoint_urls`
If enabled, the AWS CLI ignores all custom endpoint configurations specified in the `config` file. Valid values are `true` and `false`.

```

ignore_configure_endpoint_urls = true
```

###### Endpoint precedence

Endpoint configuration settings are located in multiple places, such as the system or user environment variables, local AWS configuration files, or explicitly declared on the command line as a parameter. The AWS CLI checks these endpoint settings in a particular order, and uses the endpoint setting with the highest precedence. For the endpoint precedence list, see Endpoint configuration and settings precedence.

`external_id`
Specifies a unique identifier that is used by third parties to assume a role in their customers' accounts. This maps to the `ExternalId` parameter in the `AssumeRole` operation. This parameter is needed only if the trust policy for the role specifies a value for `ExternalId`. For more information, see How to use an external ID when granting access to your AWS resources to a third party  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html> in the IAM User Guide.

`max_attempts`
Specifies a value of maximum retry attempts the AWS CLI retry handler uses, where the initial call counts toward the `max_attempts` value that you provide.

You can override this value by using the `AWS_MAX_ATTEMPTS` environment variable.

```

max_attempts = 3
```

`mfa_serial`
The identification number of an MFA device to use when assuming a role. This is mandatory only if the trust policy of the role being assumed includes a condition that requires MFA authentication. The value can be either a serial number for a hardware device (such as `GAHT12345678`) or an Amazon Resource Name (ARN) for a virtual MFA device (such as `arn:aws:iam::123456789012:mfa/`user``).

`output`
Specifies the default output format for commands requested using this profile. You can specify any of the following values:

-
json – The output is formatted as a JSON <https://json.org/> string.

-
 yaml – The output is formatted as a YAML <https://yaml.org/> string.

-
yaml-stream – The output is streamed and formatted as a YAML <https://yaml.org/> string. Streaming allows for faster handling of large data types.

-
text – The output is formatted as multiple lines of tab-separated string values. This can be useful to pass the output to a text processor, like `grep`, `sed`, or `awk`.

-
table – The output is formatted as a table using the characters +|- to form the cell borders. It typically presents the information in a "human-friendly" format that is much easier to read than the others, but not as programmatically useful.

-
off – The output suppresses all command output to stdout. This is useful in automation scripts and CI/CD pipelines where you only need to check the command's exit code without processing the output.

Can be overridden by the `AWS_DEFAULT_OUTPUT` environment variable or the `--output` command line option.

```

output = table
```

`parameter_validation`
Specifies whether the AWS CLI client attempts to validate parameters before sending them to the AWS service endpoint.

-
true – This is the default value. If specified, the AWS CLI performs local validation of command line parameters.

-
false – If specified, the AWS CLI does not validate command line parameters before sending them to the AWS service endpoint.

This entry does not have an equivalent environment variable or command line option.

```

parameter_validation = false
```

`region`
Specifies the AWS Region to send requests to for commands requested using this profile.

-
You can specify any of the Region codes available for the chosen service as listed in AWS Regions and Endpoints <https://docs.aws.amazon.com/general/latest/gr/rande.html> in the Amazon Web Services General Reference.

-
`aws_global` enables you to specify the global endpoint for services that support a global endpoint in addition to Regional endpoints, such as AWS Security Token Service (AWS STS) and Amazon Simple Storage Service (Amazon S3).

You can override this value by using the `AWS_REGION` environment variable, `AWS_DEFAULT_REGION` environment variable, or the `--region` command line option.

```

region = us-west-2
```

`request_checksum_calculation`
Specifies when a checksum is calculated for request payloads, and has the following options:

-
`when_supported` – (Default) The request payload checksum is calculated when an operation either specifies a checksum algorithm in its service model or requires request checksums.

-
`when_required` – The request payload checksum is calculated when an operation requires request checksums or when a user provides a `requestAlgorithmMember` that is modeled by the AWS service.

```

request_checksum_calculation = when_supported
```

The environment variable AWS_REQUEST_CHECKSUM_CALCULATION overrides this setting.

`response_checksum_validation`
Specifies when checksum validation is performed for response payloads, and has the following options:

-
`when_supported` – (Default) The response payload checksum validation is performed when an operation specifies a response algorithm in its service model that the AWS CLI supports.

-
`when_required` – The response payload checksum validation is performed when an operation specifies a response algorithm in its service model that the AWS CLI supports, and you set the modeled `requestValidationModeMember` to `ENABLED` in the operation input.

```

response_checksum_validation = when_supported
```

The environment variable AWS_RESPONSE_CHECKSUM_VALIDATION overrides this setting.

`retry_mode`
Specifies which retry mode AWS CLI uses. There are three retry modes available: `standard` (default), `legacy` (default), and `adaptive`. For more information on retries, see AWS CLI retries in the AWS CLI.

You can override this value by using the `AWS_RETRY_MODE` environment variable.

```

retry_mode = standard
```

`role_arn`
Specifies the Amazon Resource Name (ARN) of an IAM role that you want to use to run the AWS CLI commands. You must also specify one of the following parameters to identify the credentials that have permission to assume this role:

-
source_profile

-
credential_source

```

role_arn = arn:aws:iam::123456789012:role/role-name
```

The environment variable AWS_ROLE_ARN overrides this setting.

For more information on using web identities, see Assume role with web identity.

`role_session_name`
Specifies the name to attach to the role session. This value is provided to the `RoleSessionName` parameter when the AWS CLI calls the `AssumeRole` operation, and becomes part of the assumed role user ARN: ` arn:aws:sts::`123456789012`:assumed-role/`role_name`/`role_session_name``. This is an optional parameter. If you do not provide this value, a session name is generated automatically. This name appears in AWS CloudTrail logs for entries associated with this session.

```

role_session_name = maria_garcia_role
```

The environment variable AWS_ROLE_SESSION_NAME overrides this setting.

For more information on using web identities, see Assume role with web identity.

`services`
Specifies the service configuration to use for your profile.

```

[profile dev-s3-specific-and-global]
endpoint_url = http://localhost:1234
services = s3-specific

[services s3-specific]
s3 =
  endpoint_url = http://localhost:4567
```

For more information on the `services` section, see Section type: services.

The environment variable AWS_ROLE_SESSION_NAME overrides this setting.

For more information on using web identities, see Assume role with web identity.

``sdk_ua_app_id``
A single AWS account can be used by multiple customer applications to make calls to AWS services. Application ID identifies which source application made a set of calls using an AWS service. AWS SDKs and services don't use or interpret this value other than to surface it back in customer communications. For example, this value can be included in operational emails to uniquely identify which of your applications is associated with the notification.

The Application ID is a string with maximum length of 50 characters. Letters, numbers and the following special characters are allowed: `! $ % & * + - . , ^ _ ` | ~` By default, no value is assigned.

```

sdk_ua_app_id = prod1
```

This setting can be overwritten by using the AWS_SDK_UA_APP_ID environment variable. You can't set this value as a command line parameter.

`sigv4a_signing_region_set`
Specifies the regions to use when signing with SigV4a using a comma-delimited list. If this variable is not set, the AWS CLI uses the default used by the AWS service. If the AWS service has no default, the request signature becomes valid in all regions using a value of `*`.

```

sigv4a_signing_region_set = us-west-2, us-east-1
```

For more information on SigV4a, see AWS Signature Version 4 for API requests <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html> in the IAM User Guide

This setting can be overwritten by using the AWS_SIGV4A_SIGNING_REGION_SET environment variable. You can't set this value as a command line parameter.

`source_profile`
Specifies a named profile with long-term credentials that the AWS CLI can use to assume a role that you specified with the `role_arn` parameter. You cannot specify both `source_profile` and `credential_source` in the same profile.

```

source_profile = production-profile
```

`sso_account_id`
Specifies the AWS account ID that contains the IAM role with the permission that you want to grant to the associated IAM Identity Center user.

This setting does not have an environment variable or command line option.

```

sso_account_id = 123456789012
```

`sso_region`
Specifies the AWS Region that contains the AWS access portal host. This is separate from, and can be a different Region than the default CLI `region` parameter.

This setting does not have an environment variable or command line option.

```

sso_region = us_west-2
```

`sso_registration_scopes`
A comma-delimited list of scopes to be authorized for the `sso-session`. Scopes authorize access to IAM Identity Center bearer token authorized endpoints. A valid scope is a string, such as `sso:account:access`. This setting isn't applicable to the legacy non-refreshable configuration.

```

sso_registration_scopes = sso:account:access
```

`sso_role_name`
Specifies the friendly name of the IAM role that defines the user's permissions when using this profile.

This setting does not have an environment variable or command line option.

```

sso_role_name = ReadAccess
```

`sso_start_url`
Specifies the URL that points to the organization's AWS access portal. The AWS CLI uses this URL to establish a session with the IAM Identity Center service to authenticate its users. To find your AWS access portal URL, use one of the following:

-
Open your invitation email, the AWS access portal URL is listed.

-
Open the AWS IAM Identity Center console at https://console.aws.amazon.com/singlesignon/ <https://console.aws.amazon.com/singlesignon/>. The AWS access portal URL is listed in your settings.

This setting does not have an environment variable or command line option.

```

sso_start_url = https://my-sso-portal.awsapps.com/start
```

`use_dualstack_endpoint`
Enables the use of dual-stack endpoints to send AWS requests. To learn more about dual-stack endpoints, which support both IPv4 and IPv6 traffic, see Using Amazon S3 dual-stack endpoints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/dual-stack-endpoints.html> in the Amazon Simple Storage Service User Guide. Dual-stack endpoints are available for some services in some regions. If a dual-stack endpoint does not exist for the service or AWS Region, the request fails. Valid settings are `true` and `false`. This is disabled by default. For more information, see Set to use dual-stack endpoints for all AWS services.

 This is mutually exclusive with the `use_accelerate_endpoint` setting.

###### Endpoint precedence

Endpoint configuration settings are located in multiple places, such as the system or user environment variables, local AWS configuration files, or explicitly declared on the command line as a parameter. The AWS CLI checks these endpoint settings in a particular order, and uses the endpoint setting with the highest precedence. For the endpoint precedence list, see Endpoint configuration and settings precedence.

`use_fips_endpoint`
Some AWS services offer endpoints that support Federal Information Processing Standard (FIPS) 140-2 <http://aws.amazon.com/compliance/fips/> in some AWS Regions. When the AWS service supports FIPS, this setting specifies what FIPS endpoint the AWS CLI should use . Unlike standard AWS endpoints, FIPS endpoints use a TLS software library that complies with FIPS 140-2. These endpoints might be required by enterprises that interact with the United States government. For more information see, Set to use FIPs endpoints for all AWS services.

If this setting is enabled, but a FIPS endpoint does not exist for the service in your AWS Region, the AWS command may fail. In this case, manually specify the endpoint to use in the command using the `--endpoint-url` option or use service-specific endpoints.

###### Endpoint precedence

Endpoint configuration settings are located in multiple places, such as the system or user environment variables, local AWS configuration files, or explicitly declared on the command line as a parameter. The AWS CLI checks these endpoint settings in a particular order, and uses the endpoint setting with the highest precedence. For the endpoint precedence list, see Endpoint configuration and settings precedence.

`web_identity_token_file`
Specifies the path to a file that contains an OAuth 2.0 access token or OpenID Connect ID token that is provided by an identity provider. The AWS CLI loads the contents of this file and passes it as the `WebIdentityToken` argument to the `AssumeRoleWithWebIdentity` operation.

The environment variable `AWS_WEB_IDENTITY_TOKEN_FILE` overrides this setting.

For more information on using web identities, see Assume role with web identity.

`tcp_keepalive`
Specifies whether the AWS CLI client uses TCP keep-alive packets.

This entry does not have an equivalent environment variable or command line option.

```

tcp_keepalive = false
```

### S3 Custom command settings

Amazon S3 supports several settings that configure how the AWS CLI performs Amazon S3 operations. Some apply to all S3 commands in both the `s3api` and `s3` namespaces. Others are specifically for the S3 "custom" commands that abstract common operations and do more than a one-to-one mapping to an API operation. The `aws s3` transfer commands `cp`, `sync`, `mv`, and `rm` have additional settings you can use to control S3 transfers.

All of these options can be configured by specifying the `s3` nested setting in your `config` file. Each setting is then indented on its own line.

###### Note

These settings are entirely optional. You should be able to successfully use the `aws s3` transfer commands without configuring any of these settings. These settings are provided to enable you to tune for performance or to account for the specific environment where you are running these `aws s3` commands.

These settings are all set under a top-level `s3` key in the `config` file, as shown in the following example for the `development` profile.

```

[profile development]
s3 =
  max_concurrent_requests = 20
  max_queue_size = 10000
  multipart_threshold = 64MB
  multipart_chunksize = 16MB
  max_bandwidth = 50MB/s
  use_accelerate_endpoint = true
  addressing_style = path
```

The following settings apply to any S3 command in the `s3` or `s3api` namespaces.

`addressing_style`
Specifies which addressing style to use. This controls whether the bucket name is in the hostname or is part of the URL. Valid values are: `path`, `virtual`, and `auto`. The default value is `auto`.

There are two styles of constructing an Amazon S3 endpoint. The first is called `virtual` and includes the bucket name as part of the hostname. For example: `https://`bucketname`.s3.amazonaws.com`. Alternatively, with the `path` style, you treat the bucket name as if it is a path in the URI; for example, `https://s3.amazonaws.com/`bucketname``. The default value in the CLI is to use `auto`, which attempts to use the `virtual` style where it can, but will fall back to `path` style when required. For example, if your bucket name is not DNS compatible, the bucket name cannot be part of the hostname and must be in the path. With `auto`, the CLI will detect this condition and automatically switch to `path` style for you. If you set the addressing style to `path`, you must then ensure that the AWS Region you configured in the AWS CLI matches the Region of your bucket.

`payload_signing_enabled`
Specifies whether to SHA256 sign sigv4 payloads. By default, this is disabled for streaming uploads (`UploadPart` and `PutObject`) when using HTTPS. By default, this is set to `false` for streaming uploads (`UploadPart` and `PutObject`), but only if a `ContentMD5` is present (it is generated by default) and the endpoint uses HTTPS.

If set to true, S3 requests receive additional content validation in the form of a SHA256 checksum which is calculated for you and included in the request signature. If set to false, the checksum isn't calculated. Disabling this can be useful to reduce the performance overhead created by the checksum calculation.

`use_accelerate_endpoint`
Use the Amazon S3 Accelerate endpoint for all `s3` and `s3api` commands. The default value is false. This is mutually exclusive with the `use_dualstack_endpoint` setting.

If set to true, the AWS CLI directs all Amazon S3 requests to the `S3 Accelerate` endpoint at `s3-accelerate.amazonaws.com`. To use this endpoint, you must enable your bucket to use `S3 Accelerate`. All requests are sent using the virtual style of bucket addressing: ``my-bucket`.s3-accelerate.amazonaws.com`. Any `ListBuckets`, `CreateBucket`, and `DeleteBucket `requests aren't sent to the S3 Accelerate endpoint as that endpoint doesn't support those operations. This behavior can also be set if the `--endpoint-url` parameter is set to `https://s3-accelerate.amazonaws.com` or `http://s3-accelerate.amazonaws.com` for any `s3` or `s3api` command.

`use_dualstack_endpoint`
Enables the use of dual-stack endpoints to send `s3` and `s3api` requests. To learn more about dual-stack endpoints, which support both IPv4 and IPv6 traffic, see Using Amazon S3 dual-stack endpoints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/dual-stack-endpoints.html> in the Amazon Simple Storage Service User Guide. Dual-stack endpoints are available for some services in some regions. If a dual-stack endpoint does not exist for the service or AWS Region, the request fails. Valid settings are `true` and `false`. This is disabled by default. For more information, see Set to use dual-stack endpoints for all AWS services.

 This is mutually exclusive with the `use_accelerate_endpoint` setting.

`disable_s3_express_session_auth`
Whether to disable Amazon S3 Express session authentication for `s3` and `s3api` commands. The value must be a boolean. Defaults to false. If set to true, client will NOT use Amazon S3 Express session authentication. If set to false, default behavior will be used for determining whether to use Amazon S3 Express session authentication.

You can override this setting by using the ` AWS_S3_DISABLE_EXPRESS_SESSION_AUTH` environment variable.

The following settings apply only to commands in the `s3` namespace command set.

`max_bandwidth`
Specifies the maximum bandwidth that can be consumed for uploading and downloading data to and from Amazon S3. The default is no limit.

This limits the maximum bandwidth that the S3 commands can use to transfer data to and from Amazon S3. This value applies to only uploads and downloads; it doesn't apply to copies or deletes. The value is expressed as bytes per second. The value can be specified as:

-
An integer. For example, `1048576` sets the maximum bandwidth usage to 1 megabyte per second.

-
An integer followed by a rate suffix. You can specify rate suffixes using: `KB/s`, `MB/s`, or `GB/s`. For example, `300KB/s`, `10MB/s`.

In general, we recommend that you first try to lower bandwidth consumption by lowering `max_concurrent_requests`. If that doesn't adequately limit bandwidth consumption to the desired rate, you can use the `max_bandwidth` setting to further limit bandwidth consumption. This is because `max_concurrent_requests` controls how many threads are currently running. If you instead first lower `max_bandwidth` but leave a high `max_concurrent_requests` setting, it can result in threads having to wait unnecessarily. This can lead to excess resource consumption and connection timeouts.

`max_concurrent_requests`
Specifies the maximum number of concurrent requests. The default value is 10.

The `aws s3` transfer commands are multithreaded. At any given time, multiple Amazon S3 requests can be running. For example, when you use the command `aws s3 cp localdir s3://bucket/ --recursive` to upload files to an S3 bucket, the AWS CLI can upload the files `localdir/file1`, `localdir/file2`, and `localdir/file3` in parallel. The setting `max_concurrent_requests` specifies the maximum number of transfer operations that can run at the same time.

You might need to change this value for a few reasons:

-
Decreasing this value – On some environments, the default of 10 concurrent requests can overwhelm a system. This can cause connection timeouts or slow the responsiveness of the system. Lowering this value makes the S3 transfer commands less resource intensive. The tradeoff is that S3 transfers can take longer to complete. Lowering this value might be necessary if you use a tool to limit bandwidth.

-
Increasing this value – In some scenarios, you might want the Amazon S3 transfers to complete as quickly as possible, using as much network bandwidth as necessary. In this scenario, the default number of concurrent requests might not be sufficient to use all of the available network bandwidth. Increasing this value can improve the time it takes to complete an Amazon S3 transfer.

`max_queue_size`
Specifies the maximum number of tasks in the task queue. The default value is 1000.

The AWS CLI internally uses a model where it queues up Amazon S3 tasks that are then executed by consumers whose numbers are limited by `max_concurrent_requests`. A task generally maps to a single Amazon S3 operation. For example, a task could be a `PutObjectTask`, or a `GetObjectTask`, or an `UploadPartTask`. The rate at which tasks are added to the queue can be much faster than the rate at which consumers finish the tasks. To avoid unbounded growth, the task queue size is capped to a specific size. This setting changes the value of that maximum number.

You generally don't need to change this setting. This setting also corresponds to the number of tasks that the AWS CLI is aware of that need to be run. This means that by default the AWS CLI can only see 1000 tasks ahead. Increasing this value means that the AWS CLI can more quickly know the total number of tasks needed, assuming that the queuing rate is quicker than the rate of task completion. The tradeoff is that a larger max_queue_size requires more memory.

`multipart_chunksize`
Specifies the chunk size that the AWS CLI uses for multipart transfers of individual files. The default value is 8 MB, with a minimum of 5 MB.

When a file transfer exceeds the `multipart_threshold`, the AWS CLI divides the file into chunks of this size. This value can be specified using the same syntax as `multipart_threshold`, either as the number of bytes as an integer, or by using a size and a suffix.

`multipart_threshold`
Specifies the size threshold the AWS CLI uses for multipart transfers of individual files. The default value is 8 MB.

When uploading, downloading, or copying a file, the Amazon S3 commands switch to multipart operations if the file exceeds this size. You can specify this value in one of two ways:

-
The file size in bytes. For example, `1048576`.

-
The file size with a size suffix. You can use `KB`, `MB`, `GB`, or `TB`. For example: `10MB`, `1GB`.

###### Note

S3 can impose constraints on valid values that can be used for multipart operations. For more information, see the S3 Multipart Upload documentation <https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html> in the Amazon Simple Storage Service User Guide.

Document Conventions

Configure the AWS CLI

Environment Variables

Did this page help you? - Yes

Thanks for letting us know we're doing a good job!

If you've got a moment, please tell us what we did right so we can do more of it.

Did this page help you? - No

Thanks for letting us know this page needs work. We're sorry we let you down.

If you've got a moment, please tell us how we can make the documentation better.