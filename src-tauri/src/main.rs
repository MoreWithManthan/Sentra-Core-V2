// SENTRA CORE — Tauri desktop wrapper
// Starts the FastAPI backend as a sidecar process and opens the React UI.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, Runtime,
};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // ── System tray ──────────────────────────────────────────────
            let show  = MenuItem::with_id(app, "show",  "Open SENTRA CORE", true, None::<&str>)?;
            let quit  = MenuItem::with_id(app, "quit",  "Quit",             true, None::<&str>)?;
            let menu  = Menu::with_items(app, &[&show, &quit])?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("SENTRA CORE — Security Monitor")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                })
                .build(app)?;

            // ── Spawn FastAPI backend sidecar ─────────────────────────────
            // The backend binary must be listed as an "externalBin" sidecar
            // in tauri.conf.json. In development, run it separately.
            #[cfg(not(debug_assertions))]
            {
                use tauri_plugin_shell::ShellExt;
                let _sidecar = app
                    .shell()
                    .sidecar("sentra-backend")
                    .expect("backend sidecar not found")
                    .spawn()
                    .expect("failed to spawn backend");
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Minimise to tray instead of closing
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running SENTRA CORE");
}
