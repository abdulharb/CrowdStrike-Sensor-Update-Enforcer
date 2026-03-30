import React from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import {
  useFalconApiContext,
  FalconApiContext,
} from "./contexts/falcon-api-context";
import { Home } from "./routes/home";
import { About } from "./routes/about";
import ReactDOM from "react-dom/client";

function App() {
  const { falcon, navigation, isInitialized } = useFalconApiContext();

  if (!isInitialized) return null;

  return (
    <React.StrictMode>
      <FalconApiContext.Provider value={{ falcon, navigation, isInitialized }}>
        <HashRouter>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/sensor-release-tracker" element={<Home />} />
            <Route path="/about" element={<About />} />
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
