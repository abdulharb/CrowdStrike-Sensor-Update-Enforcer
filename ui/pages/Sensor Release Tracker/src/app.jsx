import React from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import {
  useFalconApiContext,
  FalconApiContext,
} from "./contexts/falcon-api-context";
import { Home } from "./routes/home";
import ReactDOM from "react-dom/client";
import "@shoelace-style/shoelace/dist/components/spinner/spinner.js";

function App() {
  const { falcon, navigation, isInitialized } = useFalconApiContext();

  if (!isInitialized) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh" }}>
        <sl-spinner style={{ fontSize: "2.5rem" }} />
      </div>
    );
  }

  return (
    <React.StrictMode>
      <FalconApiContext.Provider value={{ falcon, navigation, isInitialized }}>
        <HashRouter>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/sensor-release-tracker" element={<Home />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </HashRouter>
      </FalconApiContext.Provider>
    </React.StrictMode>
  );
}

const domContainer = document.querySelector("#app");
const root = ReactDOM.createRoot(domContainer);
root.render(<App />);
