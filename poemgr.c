/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <uci.h>
#include <unistd.h>
#include <json-c/json.h>

#include "poemgr.h"

extern const struct poemgr_profile poemgr_profile_uswflex;
extern const struct poemgr_profile poemgr_profile_unreal;

static const struct poemgr_profile *poemgr_profiles[] = {
	&poemgr_profile_uswflex,
	&poemgr_profile_unreal,
	NULL
};

static const struct poemgr_profile *get_profile_by_name(const char *desired_name)
{
	const struct poemgr_profile *profile, **walker;

	for (walker = poemgr_profiles; *walker; walker++) {
		profile = *walker;
		if (!strcmp(profile->name, desired_name))
			return profile;
	};

	return NULL;
}

static int uci_lookup_option_int(struct uci_context* uci, struct uci_section* s,
								 const char* name)
{
	const char* str = uci_lookup_option_string(uci, s, name);
	return str == NULL ? -1 : atoi(str);
}

static int poemgr_load_port_settings(struct poemgr_ctx *ctx, struct uci_context *uci_ctx)
{
	const char *disabled, *port, *pse_port, *name;
	struct uci_package *package;
	struct uci_element *e;
	struct uci_section *s;
	int port_idx;

	package = uci_lookup_package(uci_ctx, "poemgr");
	if (!package)
		return 1;

	/* Make sure unconfigured ports are 'disabled' */
	for (port_idx = 0; port_idx < ctx->profile->num_ports; port_idx++)
		ctx->ports[port_idx].settings.disabled = 1;

	uci_foreach_element(&package->sections, e) {
		s = uci_to_section(e);

		if (strcmp(s->type, "port"))
			continue;

		port = uci_lookup_option_string(uci_ctx, s, "port");
		pse_port = uci_lookup_option_string(uci_ctx, s, "pse_port");
		name = uci_lookup_option_string(uci_ctx, s, "name");
		disabled = uci_lookup_option_string(uci_ctx, s, "disabled");

		if (!port)
			return 1;

		port_idx = atoi(port);
		if (port_idx == -1) {
			/* No port specified */
			return 1;
		} else if (port_idx >= ctx->profile->num_ports) {
			/* Port does not exist. Ignore. */
			continue;
		}

		ctx->ports[port_idx].settings.name =  name ? strdup(name) : strdup(port);
		ctx->ports[port_idx].settings.disabled = disabled ? !!atoi(disabled) : 0;
		ctx->ports[port_idx].settings.pse_port = pse_port ? atoi(pse_port) : -1;
	}

	return 0;
}

int poemgr_load_settings(struct poemgr_ctx *ctx, struct uci_context *uci_ctx)
{
	struct uci_package *package;
	struct uci_section *section;
	const char *s;
	int ret;

	ret = 0;

	if (!uci_ctx)
		return -1;

	if (uci_load(uci_ctx, "poemgr", &package) != UCI_OK) {
		ret = -1;
		goto out;
	}

	section = uci_lookup_section(uci_ctx, package, "settings");
	if (!section || strcmp(section->type, "poemgr")) {
		ret = -1;
		goto out;
	}

	ctx->settings.disabled = !!(uci_lookup_option_int(uci_ctx, section, "disabled") > 0);

	s = uci_lookup_option_string(uci_ctx, section, "profile");
	if (!s) {
		ret = -1;
		goto out;
	}

	ctx->settings.profile = strdup(s);

out:
	return ret;
}

static json_object *poemgr_create_port_fault_array(int faults)
{
	struct json_object *arr = json_object_new_array();

	if (faults & POEMGR_FAULT_TYPE_POWER_MANAGEMENT)
		json_object_array_add(arr, json_object_new_string("power-budget-exceeded"));
	if (faults & POEMGR_FAULT_TYPE_OVER_TEMPERATURE)
		json_object_array_add(arr, json_object_new_string("over-temperature"));
	if (faults & POEMGR_FAULT_TYPE_SHORT_CIRCUIT)
		json_object_array_add(arr, json_object_new_string("short-circuit"));
	if (faults & POEMGR_FAULT_TYPE_RESISTANCE_TOO_LOW)
		json_object_array_add(arr, json_object_new_string("resistance-too-low"));
	if (faults & POEMGR_FAULT_TYPE_RESISTANCE_TOO_HIGH)
		json_object_array_add(arr, json_object_new_string("resistance-too-high"));
	if (faults & POEMGR_FAULT_TYPE_CAPACITY_TOO_HIGH)
		json_object_array_add(arr, json_object_new_string("capacity-too-high"));
	if (faults & POEMGR_FAULT_TYPE_OPEN_CIRCUIT)
		json_object_array_add(arr, json_object_new_string("open-circuit"));
	if (faults & POEMGR_FAULT_TYPE_OVER_CURRENT)
		json_object_array_add(arr, json_object_new_string("over-current"));
	if (faults & POEMGR_FAULT_TYPE_UNKNOWN)
		json_object_array_add(arr, json_object_new_string("unknown"));

	return arr;
}

struct json_object *json_float(float val)
{
	char format[16];

	snprintf(format, sizeof(format), "%.1f", val);
	return json_object_new_double_s(val, format);
}

int poemgr_show(struct poemgr_ctx *ctx)
{
	struct json_object *root_obj, *ports_obj, *port_obj, *pse_arr, *pse_obj, *input_obj, *output_obj;
	const bool has_input = !!ctx->profile->update_input_status;
	struct poemgr_pse_chip *pse_chip;
	struct poemgr_metric metric_buf;
	const char *pse_model;
	char port_idx[3];
	int ret = 0;

	if(!ctx->profile->ready(ctx)) {
		fprintf(stderr, "Profile disabled. Enable profile first.\n");
		return 1;
	}

	/* Update port status */
	for (int p_idx = 0; p_idx < ctx->profile->num_ports; p_idx++) {
		ret = ctx->profile->update_port_status(ctx, p_idx);
		if (ret)
			return ret;
	}

	/* Update input status */
	if (has_input) {
		ret = ctx->profile->update_input_status(ctx);
		if (ret)
			return ret;
	}

	/* Update output status */
	ret = ctx->profile->update_output_status(ctx);
	if (ret)
		return ret;

	/* Create JSON object */
	root_obj = json_object_new_object();

	/* Add Profile name */
	json_object_object_add(root_obj, "profile", json_object_new_string(ctx->profile->name));

	/* Get PoE input information */
	if (has_input) {
		input_obj = json_object_new_object();
		json_object_object_add(input_obj, "type",json_object_new_string(poemgr_poe_type_to_string(ctx->input_status.type)));
		json_object_object_add(root_obj, "input", input_obj);
	}

	/* Get PoE output information */
	output_obj = json_object_new_object();

	json_object_object_add(output_obj, "power_budget", json_float(ctx->output_status.power_budget));

	/* Get port information */
	ports_obj = json_object_new_object();
	for (int i = 0; i < ctx->profile->num_ports; i++) {
		snprintf(port_idx, 3, "%d", i);
		port_obj = json_object_new_object();
		json_object_object_add(port_obj, "enabled", json_object_new_boolean(!!ctx->ports[i].status.enabled));
		json_object_object_add(port_obj, "active", json_object_new_boolean(!!ctx->ports[i].status.active));
		json_object_object_add(port_obj, "poe_class", json_object_new_int(ctx->ports[i].status.poe_class));
		json_object_object_add(port_obj, "power", json_float(ctx->ports[i].status.power));
		json_object_object_add(port_obj, "power_limit", json_float(ctx->ports[i].status.power_limit));
		json_object_object_add(port_obj, "name", !!ctx->ports[i].settings.name ? json_object_new_string(ctx->ports[i].settings.name) : NULL);
		json_object_object_add(port_obj, "faults", poemgr_create_port_fault_array(ctx->ports[i].status.faults));
		/* ToDo: Export PSE specific data */

		json_object_object_add(ports_obj, port_idx, port_obj);
	}
	json_object_object_add(output_obj, "ports", ports_obj);

	json_object_object_add(root_obj, "output", output_obj);

	pse_arr = json_object_new_array();
	json_object_object_add(root_obj, "pse", pse_arr);
	for (int i = 0; i < ctx->profile->num_pse_chips; i++) {
		pse_chip = &ctx->pse_chips[i];
		pse_obj = json_object_new_object();
		json_object_array_add(pse_arr, pse_obj);

		pse_model = pse_chip->model ? pse_chip->model : "unknown";
		json_object_object_add(pse_obj, "model", json_object_new_string(pse_model));

		for (int j = 0; j < pse_chip->num_metrics; j++) {
			ret = pse_chip->export_metric(pse_chip, &metric_buf, j);
			if (ret)
				goto out;

			/* ToDo handle memory in case of error */
			switch (metric_buf.type) {
				case POEMGR_METRIC_INT32:
					json_object_object_add(pse_obj, metric_buf.name, json_object_new_int(metric_buf.val_int32));
					break;
				default:
					ret = 1;
					goto out;
			}
		}
	}


	/* Save to char pointer */
	const char *c = json_object_to_json_string_ext(root_obj, JSON_C_TO_STRING_PRETTY);

	fprintf(stdout, "%s\n", c);

out:
	json_object_put(root_obj);
	return ret;
}

int poemgr_enable(struct poemgr_ctx *ctx)
{
	if (!ctx->profile->enable)
		return 0;

	return ctx->profile->enable(ctx);
}

int poemgr_disable(struct poemgr_ctx *ctx)
{
	if (!ctx->profile->disable)
		return 0;

	return ctx->profile->disable(ctx);
}

int poemgr_reset(struct poemgr_ctx *ctx)
{
	if (!ctx->profile->reset)
		return 0;

	return ctx->profile->reset(ctx);
}

int poemgr_apply(struct poemgr_ctx *ctx)
{
	/* Implicitly enable profile. */
	poemgr_enable(ctx);

	/*
	 * The PoE chip might need a tiny moment before input detection.
	 * On a USW-Flex powered by an 802.3at injector (TL-POE160S), it initially
	 * reports a 802.3af input, which results in a low-balled power budget.
	 * After the following small nap, input is correctly read as 802.3at.
	 */
	usleep(1);

	if (!ctx->profile->apply_config)
		return 0;

	return ctx->profile->apply_config(ctx);
}

const char *sanity_check_profile(const struct poemgr_profile *profile)
{
	if (profile->num_ports > POEMGR_MAX_PORTS)
		return "too many ports";

	if (profile->num_pse_chips > POEMGR_MAX_PSE_CHIPS)
		return "too many pse chips";

	if (!profile ->init || !profile ->ready
	   || !profile ->update_port_status || !profile ->update_output_status)
		return "missing mandatory member function";

	return NULL;
}

int main(int argc, char *argv[])
{
	struct uci_context *uci_ctx = uci_alloc_context();
	const struct poemgr_profile *profile;
	struct poemgr_ctx ctx = {};
	const char *reason;
	char *action;
	int ret;

	/* Default action */
	action = POEMGR_ACTION_STRING_SHOW;

	/* Load settings */
	ret = poemgr_load_settings(&ctx, uci_ctx);
	if (ret)
		exit(1);

	/* Select profile */
	profile = get_profile_by_name(ctx.settings.profile);
	if (!profile) {
		fprintf(stderr, "No profile found for \"%s\"\n",
				 ctx.settings.profile);
		exit(1);
	}

	reason = sanity_check_profile(profile);
	if (reason) {
	    fprintf(stderr, "Profile failed sanity check: %s\n", reason);
		exit(1);
	}

	ctx.profile = profile;

	/* Load port settings (requires selected profile) */
	ret = poemgr_load_port_settings(&ctx, uci_ctx);
	if (ret)
		exit(1);

	/* Call profile init routine */
	if (profile->init(&ctx))
		exit(1);

	/* check which action we are supposed to perform */
	if (argc > 1)
		action = argv[1];

	if (!strcmp(POEMGR_ACTION_STRING_SHOW, action)) {
		/* Show */
		ret = poemgr_show(&ctx);
	} else if (!strcmp(POEMGR_ACTION_STRING_APPLY, action)) {
		/* Apply */
		ret = poemgr_apply(&ctx);
	} else if (!strcmp(POEMGR_ACTION_STRING_ENABLE, action)) {
		/* Enable */
		ret = poemgr_enable(&ctx);
	} else if (!strcmp(POEMGR_ACTION_STRING_DISABLE, action)) {
		/* Disable */
		ret = poemgr_disable(&ctx);
	} else if (!strcmp("reset", action)) {
		ret = poemgr_reset(&ctx);
	}

	if (uci_ctx)
		uci_free_context(uci_ctx);

	return ret;
}
