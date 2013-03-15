/**
 *
 * @ingroup   SLP_PG
 * @defgroup  Security_Server_PG Security Server
@{

<h1 class="pg">Introduction</h1>
<p>In Linux system, access control is enforced in the kernel space objects such as file, socket, directory, and device which are all described as files. In SLP, many objects are defined in user space which cannot be described as file, for example, make a phone call, send a SMS message, connect to the Internet, and modify SIM password. Some of the objects in user space are very sensitive to the platform and the phone business as well as user's property. Therefore the user space objects needed to be protected.</p>
<p>To protect such user space objects, there must be a kind of credential to decide access result, and the credential must be trusted. Since process has privileges and the objects only has label, so some trusted entity should check the process has right privilege to access objects, and the security hooks to check this privilege should be located in the each middleware service daemons which provide the objects to the applications.</p>
<p>Security Server uses group IDs of Linux system that are assigned to each process. In detail, if a process requests to get some user-space service to a middleware daemon, the middleware daemon requests to check privilege of some process, then the security server checks given gid is assigned to the process or not. If yes, then return yes, if no, then return no.</p>
<p>If an application and middleware daemon uses Linux standard IPC such as Unix domain socket, there is no need to introduce 3rd party process to check gid that the process has. But some of service uses non Linux standard IPC such as telephony - using dbus - which the peer's credential is not propagated to the other peer. As a result to meet all the system's environment, we introduce Security Server.</p>
<p>
Security Server uses a random token named "cookie" to identify a process, the cookie needed not to be abled to guess easily, so it's quite long (currently 20 bytes), and only kept by Security Server process memory</p>

<h1 class="pg">Security Server Architecture</h1>
@image html SLP_Security-Server_PG_image001.png
<p>Above fiture explains software architecture of Security Server. It is client-server structure, and communicates by IPC. The IPC must be point-2-point mechanism such as UNIX domain socket, not server related IPC such as dbus, because it's not easy to guarantee the other peer's security.</p>
<p>Application or middleware process can call Security Server API to assign a new cookie or checking privilege of the given cookie. In this case, client library authenticates IPC peer and check the peer is Security Server process. In the same sense, Security Server authenticates client also.</p>
<p>Application requests cookie to Security Server before requesting the service to the middleware daemon. Security Server authenticates the client, generates a random cookie, stores the cookie into local memory, and responds to the client with the cookie value. Client loads the cookie in the request message and sends to the middleware server, then the receiver middleware daemon check the privilege of the given cookie by calling Security Server API. Security Server compares received cookie value with stored cookie, checks and responds to the middleware daemon. Finally middleware daemon knows the client's privilege and it decides continue or block the request.</p>

<h2>Sub components</h2>

<h3>Client library</h3>
@image html SLP_Security-Server_PG_image002.png
<p>Client library is linked to application or middleware daemon. Therefore it belongs to the caller process, so uid, pid, and groups are also same. If the application calls cookie request API, the client compose cookie request message and sends to the Security Server and wait for the response. After receiving the response, first checks the response is from Security Server, and if it's true, it stores cookie into cookie container.</p>
<p>Middleware daemon also links same client library, but by the difference of the calling APIs, the functions are different. Middleware daemon first receives cookie value loaded in service request from the client, and then the middleware calls Security Server API to check the cookie has the privilege to the service and waits for the response. After receiving the response, it authenticates the response is really from Security Server, and continue service by the result of the API.</p>

<h3>Security Server Daemon</h3>
@image html SLP_Security-Server_PG_image003.png
<p>Security Server daemon is a Unix domain socket server, but it only has single thread and single process to get rid of race condition for the proc file system and cookie list to be shared. It’s easy to manage, more secure and the Security Server itself doesn't need to maintain a session for a long time.</p>
<p>When request API is received from the client, Security Server first parses, and authenticates the message, and creates cookie or checks privilege. Cookie is a 20 bytes random string too hard to be guessed. So it's hard to be spoofed.</p>
<p>Cookie generator generates a cookie based on proc file system information of the client process with group IDs the client belongs to, and privilege checker searches received cookie value with stored cookie list and checks the privilege.</p>
<p>Cookie list is a linked list implemented in memory and it stores and manages generated cookie.</p>

<h1 class="pg">Dependency</h1>
<p>The Security Server has high dependency on Linux kernel, precisely the proc file system. Since Security Server refers to proc file system with processes group ID, so the kernel must support group ID representation on the proc file system.</p>
<p>In kernel version 2.6, there is a file in proc file system "/proc/[pid]/status" which describes various information about the process as text, it has a line named "Groups:" and it lists the group IDs that the process is belonged to. But there is a drawback in this file, it only shows at most 32 group IDs, if number of groups of the process is bigger than 32, it ignores them.</p>
<p>To enable to show all the groups you have to patch the kernel source code to show more groups than 32, but there is another drawback. All files in the proc file system has size limit to 4k bytes because the file buffer size is 4k bytes, so it's not possible to show all possible groups of the process (64k), but currently number of all groups in the LiMo platform is much lower than the size, so it's not a big problem. But near future we need to apply this patch into kernel mainline source code by any form.</p>

<h1 class="pg">Scenarios</h1>
@image html SLP_Security-Server_PG_image004.png
<p>Security Server process view is described in figure above. It's explained in above, so it's not necessary to explain again. But one possible question may arise, that why do we need Security Server, that the service daemon can authenticates application process by the IPC, and the daemon can check proc file system by itself, so it seems that we may not need to have Security Server at all<p>
@image html SLP_Security-Server_PG_image005.png
<p>But there is exceptional process view described in figure above. If the middleware's IPC mechanism is dbus, then the daemon cannot guarantee the identity of the requesting application. In this case, there is no possible way to check and authenticate application from the middleware daemon directly. We need a trusted 3rd party to guarantee such identity and privilege, therefore Security Server is required.</p>
<p>As described above, the cookie value is the key of the security of Security Server. The cookie value must not to be exposed into the platform, the cookie value must be stored securely that only Security Server and the application process knows the value. Even the middleware daemon should not cache the cookie for the security reason</p>

<h1 class="pg">APIs</h1>

<h3 class="pg">security_server_get_gid</h3>
<table>
	<tr>
		<td>
			API Name:
		</td>
		<td>
			gid_t security_server_get_gid(const char *object)
		</td>
	</tr>
	<tr>
		<td>
			Input Parameter:
		</td>
		<td>
			object name as Null terminated string
		</td>
	</tr>
	<tr>
		<td>
			Output Parameter:
		</td>
		<td>
			N/A
		</td>
	</tr>
	<tr>
		<td>
			Return value:
		</td>
		<td>
			On success, returns the integer gid of requested object.<br>
			On fail, returns negative integer
		</td>
	</tr>
</table>
This API returns the gid from given object name. This API is only allowed to be called from middleware service daemon which is running under root privilege

<h3 class="pg">security_server_get_object_name</h3>
<table>
	<tr>
		<td>
			API Name:
		</td>
		<td>
			int security_server_get_object_name(gid_t gid, char *object, size_t max_object_size)
		</td>
	</tr>
	<tr>
		<td>
			Input Parameter:
		</td>
		<td>
			gid, max_object_size
		</td>
	</tr>
	<tr>
		<td>
			Output Parameter:
		</td>
		<td>
			object as null terminated string
		</td>
	</tr>
	<tr>
		<td>
			Return value:
		</td>
		<td>
			On success, returns 0<br>
			On fail, returns negative integer
		</td>
	</tr>
</table>
This API is opposite with security_server_get_gid(). It converts given gid to object name which buffer size is max_object_size. If object name is bigger then max_object_size then it returns SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMAL error.

<h3 class="pg">security_server_request_cookie</h3>
<table>
	<tr>
		<td>
			API Name:
		</td>
		<td>
			gid_t security_server_request_cookie(char *cookie, size_t max_cookie)
		</td>
	</tr>
	<tr>
		<td>
			Input Parameter:
		</td>
		<td>
			max_cookie
		</td>
	</tr>
	<tr>
		<td>
			Output Parameter:
		</td>
		<td>
			cookie
		</td>
	</tr>
	<tr>
		<td>
			Return value:
		</td>
		<td>
			On success, returns 0<br>
			On fail, returns negative integer
		</td>
	</tr>
</table>
This API requests a cookie to Security Server. max_cookie is the size of buffer cookie to be filled with cookie value, if max_cookie smaller then cookie size, then this API returns SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMAL error.

<h3 class="pg">security_server_get_cookie_size</h3>
<table>
	<tr>
		<td>
			API Name:
		</td>
		<td>
			int security_server_get_cookie_size(void)
		</td>
	</tr>
	<tr>
		<td>
			Input Parameter:
		</td>
		<td>
			N/A
		</td>
	</tr>
	<tr>
		<td>
			Output Parameter:
		</td>
		<td>
			N/A
		</td>
	</tr>
	<tr>
		<td>
			Return value:
		</td>
		<td>
			size of cookie value
		</td>
	</tr>
</table>
This API simply returns the size of cookie.

<h3 class="pg">security_server_check_privilege</h3>
<table>
	<tr>
		<td>
			API Name:
		</td>
		<td>
			int security_server_check_privilege(const char *cookie, gid_t privilege)
		</td>
	</tr>
	<tr>
		<td>
			Input Parameter:
		</td>
		<td>
			cookie, privilege
		</td>
	</tr>
	<tr>
		<td>
			Output Parameter:
		</td>
		<td>
			N/A
		</td>
	</tr>
	<tr>
		<td>
			Return value:
		</td>
		<td>
			On success, returns 0<br>
			On fail, returns negative integer
		</td>
	</tr>
</table>
This API checks the cookie value has privilege for given gid. This API should be called by middleware server only after application embed cookie into the request message and sent to the middleware server. The middleware server should aware with the privilege parameter because it knows the object which the client application tries to access.


<h1 class="pg">Implementation Guide</h1>

<h2>Middleware server side</h2>
<p>
In middleware, implementation is focused on checking privilege of the requested client application. To call security_server_check_privilege() API, you have to get the gid value first, and this can be achieved by calling security_server_get_gid() API. The pre-condition of this scenario is that the middleware server knows the name of the object. Once you get the gid values, you can cache them for better performance. </p>
<p>
Once a client application requests to access the middleware’s object, the client should embed cookie into the request message. If not, the security is not guaranteed. After getting request and embedded cookie, the middleware server call security_server_check_privilege() API to check the client is allowed to access the object, the security server will respond the result. Finally the server need to decide continue the service or not.</p>

@code
static gid_t g_gid;

int get_gid()
{
	int ret;
	// Get gid of telephony call - example object
	ret = security_server_get_gid("telephony_call");
	if(ret < 0)
	{
		return -1;
	}
	g_gid = ret;
	return 0;
}

int main(int argc, char * argv[])
{
	char *cookie = NULL;
	int ret, cookie_size;


	...


		// Initially get gid about the object which is interested in
		if(get_gid() < 0)
			exit(-1);

	// get cookie size and malloc it if you want
	cookie_size = security_server_get_cookie_size();
	cookie = malloc(cookie_size);

	...

	// If a request has been received
	// First parse the request and get the cookie value
	// Let's assume that the buffer cookie is filled with received cookie value
	ret = security_server_check_privilege(cookie, cookie_size);
	if(ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
	{
		// Access denied
		// Send error message to client application
	}
	else if( ret != SECURITY_SERVER_SUCCESS)
	{
		// Error occurred
		// Check error condition 
	}
	else
	{
		// Access granted
		// Continue service
		...
	}


	...


	free(cookie);
	...
}
@endcode

<h2>Client application side</h2>
<p>
In client application, what you need is just request a cookie and embed it into request message</p>

@code
int some_platform_api()
{
	char *cookie = NULL;
	int cookie_size, ret;

	...


	// malloc the cookie
	cookie_size = security_server_get_cookie_size();
	cookie = malloc(cookie_size);

	...


		// Request cookie from the security server
		ret = security_server_request_cookie(cookie, cookie_size);
	if(ret < 0)
	{
		// Some error occurred
		return -1;
	}

	// embed cookie into the message and send to the server

	...
	free(cookie);
}
@endcode

*/
/**
*@}
*/
