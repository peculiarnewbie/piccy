import handler from "@tanstack/solid-start/server-entry";

export default {
    async fetch(request) {
        return handler.fetch(request);
    },
} as ExportedHandler<Env>;
