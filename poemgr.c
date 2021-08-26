#include <stdlib.h>
#include <string.h>
#include <uci.h>
#include <json-c/json.h>

#include "poemgr.h"

extern struct poemgr_profile poemgr_profile_uswflex;

static struct poemgr_profile *poemgr_profiles[] = {
	&poemgr_profile_uswflex,
	NULL
};

static int uci_lookup_option_int(struct uci_context* uci, struct uci_section* s,
								 const char* name)
{
	const char* str = uci_lookup_option_string(uci, s, name);
	return str == NULL ? -1 : atoi(str);
}

static int load_port_settings(struct poemgr_ctx *ctx, struct uci_context *uci_ctx)
{
	struct uci_package *package;
	struct uci_element *e;
	struct uci_section *s;
	int ret = 0;

	package = uci_lookup_package(uci_ctx, "poemgr");

	if (!package) {
		ret = 1;
		goto out;
	}

	uci_foreach_element(&package->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *disabled;
		const char *port;
		const char *name;
		int port_idx;

		if (strcmp(s->type, "port"))
			continue;

		port = uci_lookup_option_string(uci_ctx, s, "port");
		name = uci_lookup_option_string(uci_ctx, s, "name");
		disabled = uci_lookup_option_string(uci_ctx, s, "disabled");

		if (!port) {
			ret = 1;
			goto out;
		}

		port_idx = atoi(port);
		if (port_idx == -1) {
			/* No port specified */
			ret = 1;
			goto out;
		} else if (port_idx >= ctx->profile->num_ports) {
			/* Port does not exist. Ignore. */
			continue;
		}

		ctx->ports[port_idx].settings.name =  name ? strdup(name) : strdup(port);
		ctx->ports[port_idx].settings.disabled = disabled ? !!atoi(disabled) : 0;
	}
out:
	return ret;
}

int load_settings(struct poemgr_ctx *ctx)
{
	struct uci_context *uci_ctx = uci_alloc_context();
	struct uci_package *package;
	struct uci_section *section;
	const char *s;
	int enabled;
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

	ctx->settings.enabled = uci_lookup_option_int(uci_ctx, section, "enabled");
	if (ctx->settings.enabled == -1) {
		ret = -1;
		goto out;
	}


	s = uci_lookup_option_string(uci_ctx, section, "profile");
	if (!s) {
		ret = -1;
		goto out;
	}

	ctx->settings.profile = strdup(s);

	ret = load_port_settings(ctx, uci_ctx);
out:
	if (uci_ctx);
		uci_free_context(uci_ctx);

	return ret;
}

int poemgr_show(struct poemgr_ctx *ctx)
{
	struct json_object *root_obj, *ports_obj, *port_obj, *pse_arr, *pse_obj, *input_obj, *output_obj;
	struct poemgr_pse_chip *pse_chip;
	struct poemgr_metric metric_buf;
	char port_idx[3];
	int ret = 0;

	/* Update port status */
	for (int p_idx = 0; p_idx < ctx->profile->num_ports; p_idx++) {
		ret = ctx->profile->update_port_status(ctx, p_idx);
		if (ret)
			goto out;
	}

	/* Update input status */
	ret = ctx->profile->update_input_status(ctx);
	if (ret)
		goto out;

	/* Update output status */
	ret = ctx->profile->update_output_status(ctx);
	if (ret)
		goto out;

	/* Create JSON object */
	root_obj = json_object_new_object();

	/* Add Profile name */
	json_object_object_add(root_obj, "profile", json_object_new_string(ctx->profile->name));

	/* Get PoE input information */
	input_obj = json_object_new_object();
	json_object_object_add(input_obj, "type", json_object_new_string(poemgr_poe_type_to_string(ctx->input_status.type)));
	json_object_object_add(root_obj, "input", input_obj);

	/* Get PoE output information */
	output_obj = json_object_new_object();

	json_object_object_add(output_obj, "power_budget", json_object_new_int(ctx->output_status.power_budget));

	/* Get port information */
	ports_obj = json_object_new_object();
	for (int i = 0; i < ctx->profile->num_ports; i++) {
		snprintf(port_idx, 3, "%d", i);
		port_obj = json_object_new_object();
		json_object_object_add(port_obj, "enabled", json_object_new_boolean(!!ctx->ports[i].status.enabled));
		json_object_object_add(port_obj, "active", json_object_new_boolean(!!ctx->ports[i].status.active));
		json_object_object_add(port_obj, "power", json_object_new_int(ctx->ports[i].status.power));
		json_object_object_add(port_obj, "power_limit", json_object_new_int(ctx->ports[i].status.power_limit));

		/* ToDo: Export PSE specific data */

		json_object_object_add(ports_obj, port_idx, port_obj);
	}
	json_object_object_add(output_obj, "ports", ports_obj);

	json_object_object_add(root_obj, "output", output_obj);

	pse_arr = json_object_new_array();
	json_object_object_add(root_obj, "pse", pse_arr);
	for (int i = 0; i < ctx->profile->num_pse_chips; i++) {
		pse_chip = &ctx->profile->pse_chips[i];
		pse_obj = json_object_new_object();
		json_object_array_add(pse_arr, pse_obj);

		json_object_object_add(pse_obj, "model", json_object_new_string(pse_chip->model));

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

int poemgr_apply(struct poemgr_ctx *ctx)
{
	if (!ctx->profile->apply_config)
		return 0;
	
	return ctx->profile->apply_config(ctx);
}

int main(int argc, char *argv[])
{
	static struct poemgr_profile *profile;
	struct poemgr_ctx ctx;
	char *action;
	int ret;

	/* Default action */
	action = POEMGR_ACTION_STRING_SHOW;

	/* Load settings */
	ret = load_settings(&ctx);
	if (ret)
		exit(1);

	/* Select profile */
	profile = poemgr_profiles[0];
	while (1) {
		if (!strcmp(profile->name, ctx.settings.profile) || profile == NULL) {
			break;
		}
	}

	if (profile == NULL)
		exit(1);

	ctx.profile = profile;
	if (profile->init(&ctx))
		exit(1);

	/* check which action we are supposed to perform */
	if (argc > 1)
		action = argv[1];
	
	if (!strcmp(POEMGR_ACTION_STRING_SHOW, action)) {
		/* Show */
		poemgr_show(&ctx);
	} else if (!strcmp(POEMGR_ACTION_STRING_APPLY, action)) {
		/* Apply */
		poemgr_apply(&ctx);
	}

	return 0;
}
