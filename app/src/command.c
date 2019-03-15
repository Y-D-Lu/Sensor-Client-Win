#include "command.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "log.h"
#include "str_util.h"

static const char *adb_command;

static inline const char *get_adb_command(void) {
    if (!adb_command) {
        adb_command = getenv("ADB");
        if (!adb_command)
            adb_command = "adb";
    }
    return adb_command;
}

static void show_adb_err_msg(enum process_result err) {
    switch (err) {
        case PROCESS_ERROR_GENERIC:
            LOGE("Failed to execute adb");
            break;
        case PROCESS_ERROR_MISSING_BINARY:
            LOGE("'adb' command not found (make it accessible from your PATH "
                  "or define its full path in the ADB environment variable)");
            break;
        case PROCESS_SUCCESS:
            /* do nothing */
            break;
    }
}

process_t adb_execute(const char *serial, const char *const adb_cmd[], int len) {
    const char *cmd[256]; // ori const char *cmd[len + 4];
    int i;
    process_t process;
    cmd[0] = get_adb_command();
    if (serial) {
        cmd[1] = "-s";
        cmd[2] = serial;
        i = 3;
    } else {
        i = 1;
    }

    memcpy(&cmd[i], adb_cmd, len * sizeof(const char *));
    cmd[len + i] = NULL;
    enum process_result r = cmd_execute(cmd[0], cmd, &process);
    if (r != PROCESS_SUCCESS) {
        show_adb_err_msg(r);
        return PROCESS_NONE;
    }
    return process;
}

process_t adb_forward(const char *serial, uint16_t local_port, const char *device_socket_name) {
    char local[4 + 5 + 1]; // tcp:PORT
    char remote[108 + 14 + 1]; // localabstract:NAME
    sprintf(local, "tcp:%" PRIu16, local_port);
    snprintf(remote, sizeof(remote), "localabstract:%s", device_socket_name);
    const char *const adb_cmd[] = {"forward", local, remote};
    return adb_execute(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t adb_forward_remove(const char *serial, uint16_t local_port) {
    char local[4 + 5 + 1]; // tcp:PORT
    sprintf(local, "tcp:%" PRIu16, local_port);
    const char *const adb_cmd[] = {"forward", "--remove", local};
    return adb_execute(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t adb_reverse(const char *serial, const char *device_socket_name, uint16_t local_port) {
    char local[4 + 5 + 1]; // tcp:PORT
    char remote[108 + 14 + 1]; // localabstract:NAME
    sprintf(local, "tcp:%" PRIu16, local_port);
    snprintf(remote, sizeof(remote), "localabstract:%s", device_socket_name);
    const char *const adb_cmd[] = {"reverse", remote, local};
    return adb_execute(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t adb_reverse_remove(const char *serial, const char *device_socket_name) {
    char remote[108 + 14 + 1]; // localabstract:NAME
    snprintf(remote, sizeof(remote), "localabstract:%s", device_socket_name);
    const char *const adb_cmd[] = {"reverse", "--remove", remote};
    return adb_execute(serial, adb_cmd, ARRAY_LEN(adb_cmd));
}

process_t adb_push(const char *serial, const char *local, const char *remote) {
#ifdef __WINDOWS__
    // Windows will parse the string, so the paths must be quoted
    // (see sys/win/command.c)
    local = strquote(local);
    if (!local) {
        return PROCESS_NONE;
    }
    remote = strquote(remote);
    if (!remote) {
        free((void *) local);
        return PROCESS_NONE;
    }
#endif

    const char *const adb_cmd[] = {"push", local, remote};
    process_t proc = adb_execute(serial, adb_cmd, ARRAY_LEN(adb_cmd));

#ifdef __WINDOWS__
    free((void *) remote);
    free((void *) local);
#endif

    return proc;
}

process_t adb_install(const char *serial, const char *local) {
#ifdef __WINDOWS__
    // Windows will parse the string, so the local name must be quoted
    // (see sys/win/command.c)
    local = strquote(local);
    if (!local) {
        return PROCESS_NONE;
    }
#endif

    const char *const adb_cmd[] = {"install", "-r", local};
    process_t proc = adb_execute(serial, adb_cmd, ARRAY_LEN(adb_cmd));

#ifdef __WINDOWS__
    free((void *) local);
#endif

    return proc;
}

SDL_bool process_check_success(process_t proc, const char *name) {
    if (proc == PROCESS_NONE) {
        LOGE("Could not execute \"%s\"", name);
        return SDL_FALSE;
    }
    exit_code_t exit_code;
    if (!cmd_simple_wait(proc, &exit_code)) {
        if (exit_code != NO_EXIT_CODE) {
            LOGE("\"%s\" returned with value %" PRIexitcode, name, exit_code);
        } else {
            LOGE("\"%s\" exited unexpectedly", name);
        }
        return SDL_FALSE;
    }
    return SDL_TRUE;
}


static int build_cmd(char *cmd, size_t len, const char *const argv[]) {
	// Windows command-line parsing is WTF:
	// <http://daviddeley.com/autohotkey/parameters/parameters.htm#WINPASS>
	// only make it work for this very specific program
	// (don't handle escaping nor quotes)
	size_t ret = xstrjoin(cmd, argv, ' ', len);
	if (ret >= len) {
		LOGE("Command too long (%" PRIsizet " chars)", len - 1);
		return -1;
	}
	return 0;
}

enum process_result cmd_execute(const char *path, const char *const argv[], HANDLE *handle) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);

	char cmd[256];
	if (build_cmd(cmd, sizeof(cmd), argv)) {
		*handle = NULL;
		return PROCESS_ERROR_GENERIC;
	}

#ifdef WINDOWS_NOCONSOLE
	int flags = CREATE_NO_WINDOW;
#else
	int flags = 0;
#endif
	LOGI("cmd path : %s , code: %s", path, cmd);
	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
		DWORD err = GetLastError();
		LOGE("CreateProcess Failed! %d", err);
		*handle = NULL;
		if (err == ERROR_FILE_NOT_FOUND) {
			return PROCESS_ERROR_MISSING_BINARY;
		}
		return PROCESS_ERROR_GENERIC;
	}

	*handle = pi.hProcess;
	return PROCESS_SUCCESS;
}

SDL_bool cmd_terminate(HANDLE handle) {
	return TerminateProcess(handle, 1) && CloseHandle(handle);
}

SDL_bool cmd_simple_wait(HANDLE handle, DWORD *exit_code) {
	DWORD code;
	if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0 || !GetExitCodeProcess(handle, &code)) {
		// cannot wait or retrieve the exit code
		code = -1; // max value, it's unsigned
	}
	if (exit_code) {
		*exit_code = code;
	}
	return !code;
}
