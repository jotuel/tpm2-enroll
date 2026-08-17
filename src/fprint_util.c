#include "fprint_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>

typedef struct {
    GMainLoop *loop;
    int result;
    bool debug;
} verify_data_t;

static void on_verify_status_signal(GDBusConnection *connection,
                                   const gchar *sender_name,
                                   const gchar *object_path,
                                   const gchar *interface_name,
                                   const gchar *signal_name,
                                   GVariant *parameters,
                                   gpointer user_data) {
    (void)connection;
    (void)sender_name;
    (void)object_path;
    (void)interface_name;
    (void)signal_name;

    verify_data_t *vd = (verify_data_t *)user_data;
    const gchar *status = NULL;
    gboolean done = FALSE;

    g_variant_get(parameters, "(&sb)", &status, &done);

    if (vd->debug) {
        fprintf(stderr, "[pam_bio_tpm2] fprintd signal: status='%s', done=%d\n",
                status, done);
    }

    if (g_strcmp0(status, "verify-match") == 0) {
        vd->result = 0; /* Success */
        if (g_main_loop_is_running(vd->loop)) {
            g_main_loop_quit(vd->loop);
        }
    } else if (g_strcmp0(status, "verify-no-match") == 0) {
        vd->result = -1;
        if (done && g_main_loop_is_running(vd->loop)) {
            g_main_loop_quit(vd->loop);
        }
    } else if (done) {
        vd->result = -2;
        if (g_main_loop_is_running(vd->loop)) {
            g_main_loop_quit(vd->loop);
        }
    }
}

static gboolean on_timeout(gpointer user_data) {
    verify_data_t *vd = (verify_data_t *)user_data;
    if (vd->debug) {
        fprintf(stderr, "[pam_bio_tpm2] fprintd verification timed out.\n");
    }
    vd->result = -ETIMEDOUT;
    if (g_main_loop_is_running(vd->loop)) {
        g_main_loop_quit(vd->loop);
    }
    return G_SOURCE_REMOVE;
}

int fprint_verify_user(const char *username, int timeout_seconds, bool debug) {
    if (!username || strlen(username) == 0) return -1;
    if (timeout_seconds <= 0) timeout_seconds = 15;

    GError *error = NULL;
    GDBusConnection *bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (!bus) {
        if (debug) {
            fprintf(stderr, "[pam_bio_tpm2] Failed to connect to system D-Bus: %s\n",
                    error ? error->message : "unknown");
        }
        if (error) g_error_free(error);
        return -1;
    }

    /* 1. Get default device path from fprintd manager */
    GDBusProxy *manager_proxy = g_dbus_proxy_new_sync(
        bus,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "net.reactivated.Fprint",
        "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager",
        NULL,
        &error
    );

    if (!manager_proxy) {
        if (debug) {
            fprintf(stderr, "[pam_bio_tpm2] Failed to create fprintd manager proxy: %s\n",
                    error ? error->message : "unknown");
        }
        if (error) g_error_free(error);
        g_object_unref(bus);
        return -1;
    }

    GVariant *res = g_dbus_proxy_call_sync(
        manager_proxy,
        "GetDefaultDevice",
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (!res) {
        if (debug) {
            fprintf(stderr, "[pam_bio_tpm2] fprintd GetDefaultDevice call failed: %s\n",
                    error ? error->message : "no device found");
        }
        if (error) g_error_free(error);
        g_object_unref(manager_proxy);
        g_object_unref(bus);
        return -1;
    }

    const gchar *dev_path = NULL;
    g_variant_get(res, "(&o)", &dev_path);

    GDBusProxy *dev_proxy = g_dbus_proxy_new_sync(
        bus,
        G_DBUS_PROXY_FLAGS_NONE,
        NULL,
        "net.reactivated.Fprint",
        dev_path,
        "net.reactivated.Fprint.Device",
        NULL,
        &error
    );

    g_variant_unref(res);
    g_object_unref(manager_proxy);

    if (!dev_proxy) {
        if (error) g_error_free(error);
        g_object_unref(bus);
        return -1;
    }

    /* 2. Claim device */
    res = g_dbus_proxy_call_sync(
        dev_proxy,
        "Claim",
        g_variant_new("(s)", username),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (!res) {
        if (debug) {
            fprintf(stderr, "[pam_bio_tpm2] Claim device failed for user '%s': %s\n",
                    username, error ? error->message : "unknown");
        }
        if (error) g_error_free(error);
        g_object_unref(dev_proxy);
        g_object_unref(bus);
        return -1;
    }
    g_variant_unref(res);

    /* 3. Subscribe to VerifyStatus signal */
    verify_data_t vd = {
        .loop = g_main_loop_new(NULL, FALSE),
        .result = -1,
        .debug = debug
    };

    guint sub_id = g_dbus_connection_signal_subscribe(
        bus,
        "net.reactivated.Fprint",
        "net.reactivated.Fprint.Device",
        "VerifyStatus",
        dev_path,
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_verify_status_signal,
        &vd,
        NULL
    );

    /* 4. Start verification */
    res = g_dbus_proxy_call_sync(
        dev_proxy,
        "VerifyStart",
        g_variant_new("(s)", "any"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (!res) {
        if (debug) {
            fprintf(stderr, "[pam_bio_tpm2] VerifyStart failed: %s\n",
                    error ? error->message : "unknown");
        }
        if (error) g_error_free(error);
        g_dbus_connection_signal_unsubscribe(bus, sub_id);
        g_dbus_proxy_call_sync(dev_proxy, "Release", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
        g_object_unref(dev_proxy);
        g_main_loop_unref(vd.loop);
        g_object_unref(bus);
        return -1;
    }
    g_variant_unref(res);

    /* Set timeout timer */
    guint timer_id = g_timeout_add_seconds(timeout_seconds, on_timeout, &vd);

    /* Run GLib main loop until signal received or timeout */
    g_main_loop_run(vd.loop);

    /* Cleanup timer and signal subscription */
    g_source_remove(timer_id);
    g_dbus_connection_signal_unsubscribe(bus, sub_id);

    /* Stop Verification and Release Device */
    g_dbus_proxy_call_sync(dev_proxy, "VerifyStop", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
    g_dbus_proxy_call_sync(dev_proxy, "Release", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);

    g_main_loop_unref(vd.loop);
    g_object_unref(dev_proxy);
    g_object_unref(bus);

    return vd.result;
}
