import React from "react";
import ReactDOM from "react-dom/client";
import SlSpinner from "@shoelace-style/shoelace/dist/react/spinner/index.js";
import {
  useFalconApiContext,
  FalconApiContext,
} from "./contexts/falcon-api-context";
import { Home } from "./routes/home";

// Single-view page: no router needed. Home renders for any path, including
// the nav link's /sensor-release-tracker.
function App() {
  const { falcon, navigation, isInitialized } = useFalconApiContext();

  if (!isInitialized) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh" }}>
        <SlSpinner style={{ fontSize: "2.5rem" }} />
      </div>
    );
  }

  return (
    <React.StrictMode>
      <FalconApiContext.Provider value={{ falcon, navigation, isInitialized }}>
        <Home />
      </FalconApiContext.Provider>
    </React.StrictMode>
  );
}

const domContainer = document.querySelector("#app");
const root = ReactDOM.createRoot(domContainer);
root.render(<App />);
