open Pervasiveext

type event_record = 
    | Session of          [`Session ] Ref.t * API.session_t option
    | Task of             [`task ] Ref.t * API.task_t option
    | Event of            [`Event] Ref.t * API.event_t option
    | VM of               [`VM] Ref.t * API.vM_t option
    | VM_metrics of       [`VM_metrics] Ref.t * API.vM_metrics_t option
    | VM_guest_metrics of [`VM_guest_metrics] Ref.t * API.vM_guest_metrics_t option
    | Host of             [`host] Ref.t * API.host_t option
    | Host_metrics of     [`host_metrics] Ref.t * API.host_metrics_t option
    | Host_cpu of         [`host_cpu] Ref.t * API.host_cpu_t option
    | Network of          [`network] Ref.t * API.network_t option
    | VIF of              [`VIF] Ref.t * API.vIF_t option
    | VIF_metrics of      [`VIF_metrics] Ref.t * API.vIF_metrics_t option
    | PIF of              [`PIF] Ref.t * API.pIF_t option
    | PIF_metrics of      [`PIF_metrics] Ref.t * API.pIF_metrics_t option
    | SR of               [`SR] Ref.t * API.sR_t option
    | VDI of              [`VDI] Ref.t * API.vDI_t option
    | VBD of              [`VBD] Ref.t * API.vBD_t option
    | VBD_metrics of      [`VBD_metrics] Ref.t * API.vBD_metrics_t option
    | PBD of              [`PBD] Ref.t * API.pBD_t option
    | Crashdump of        [`Crashdump] Ref.t * API.crashdump_t option
    | VTPM of             [`VTPM] Ref.t *  API.vTPM_t option
    | Console of          [`Console] Ref.t * API.console_t option
    | User of             [`User] Ref.t * API.user_t option
    | Pool of             [`pool] Ref.t *  API.pool_t option
    | Message of          [`message] Ref.t * API.message_t option

let record_of_event ev =
  let xmlrpc = ev.Event_types.snapshot in
  match ev.Event_types.ty with
    | "session" ->          Session (Ref.of_string ev.Event_types.reference, may (API.From.session_t "") xmlrpc)
    | "task" ->             Task (Ref.of_string ev.Event_types.reference, may (API.From.task_t "") xmlrpc)
    | "event" ->            Event (Ref.of_string ev.Event_types.reference, may (API.From.event_t "") xmlrpc)
    | "vm" ->               VM (Ref.of_string ev.Event_types.reference, may (API.From.vM_t "") xmlrpc)
    | "vm_metrics" ->       VM_metrics (Ref.of_string ev.Event_types.reference, may (API.From.vM_metrics_t "") xmlrpc)
    | "vm_guest_metrics" -> VM_guest_metrics (Ref.of_string ev.Event_types.reference, may (API.From.vM_guest_metrics_t "") xmlrpc)
    | "host" ->             Host (Ref.of_string ev.Event_types.reference, may (API.From.host_t "") xmlrpc)
    | "host_metrics" ->     Host_metrics (Ref.of_string ev.Event_types.reference, may (API.From.host_metrics_t "") xmlrpc)
    | "host_cpu" ->         Host_cpu (Ref.of_string ev.Event_types.reference, may (API.From.host_cpu_t "") xmlrpc)
    | "network" ->          Network (Ref.of_string ev.Event_types.reference, may (API.From.network_t "") xmlrpc)
    | "vif" ->              VIF (Ref.of_string ev.Event_types.reference, may (API.From.vIF_t "") xmlrpc)
    | "vif_metrics" ->      VIF_metrics (Ref.of_string ev.Event_types.reference, may (API.From.vIF_metrics_t "") xmlrpc)
    | "pif" ->              PIF (Ref.of_string ev.Event_types.reference, may (API.From.pIF_t "") xmlrpc)
    | "pif_metrics" ->      PIF_metrics (Ref.of_string ev.Event_types.reference, may (API.From.pIF_metrics_t "") xmlrpc)
    | "sr" ->               SR (Ref.of_string ev.Event_types.reference, may (API.From.sR_t "") xmlrpc)
    | "vdi" ->              VDI (Ref.of_string ev.Event_types.reference, may (API.From.vDI_t "") xmlrpc)
    | "vbd" ->              VBD (Ref.of_string ev.Event_types.reference, may (API.From.vBD_t "") xmlrpc)
    | "vbd_metrics" ->      VBD_metrics (Ref.of_string ev.Event_types.reference, may (API.From.vBD_metrics_t "") xmlrpc)
    | "pbd" ->              PBD (Ref.of_string ev.Event_types.reference, may (API.From.pBD_t "") xmlrpc)
    | "crashdump" ->        Crashdump (Ref.of_string ev.Event_types.reference, may (API.From.crashdump_t "") xmlrpc)
    | "vtpm" ->             VTPM (Ref.of_string ev.Event_types.reference, may (API.From.vTPM_t "") xmlrpc)
    | "console" ->          Console (Ref.of_string ev.Event_types.reference, may (API.From.console_t "") xmlrpc)
    | "user" ->             User (Ref.of_string ev.Event_types.reference, may (API.From.user_t "") xmlrpc)
    | "pool" ->             Pool (Ref.of_string ev.Event_types.reference, may (API.From.pool_t "") xmlrpc)
    | "message" ->          Message (Ref.of_string ev.Event_types.reference, may (API.From.message_t "") xmlrpc)


