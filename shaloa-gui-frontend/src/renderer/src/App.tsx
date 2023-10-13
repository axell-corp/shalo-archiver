import {
  Box,
  Heading,
  Tabs,
  TabList,
  Tab,
  TabPanel,
  TabPanels
} from "@chakra-ui/react";
import AutoDecode from "./pages/AutoDecode";
import CreateKey from "./pages/CreateKey";
import Decode from "./pages/Decode";
import Encode from "./pages/Encode";
import ImportKey from "./pages/ImportKey";

const App: React.FC = () => {
  const filepath =
    new URLSearchParams(new URL(window.location.href).search).get("filepath") ??
    undefined;

  if (filepath) {
    return (
      <Box m={2}>
        <AutoDecode filePath={filepath} />
      </Box>
    );
  } else {
    return (
      <Box m={2}>
        <Heading>shaloArchiver</Heading>
        <Box marginBlock={4}>
          <Tabs variant="enclosed-colored">
            <TabList>
              <Tab>暗号化</Tab>
              <Tab>復号</Tab>
              <Tab>鍵生成</Tab>
              <Tab>鍵インポート</Tab>
            </TabList>
            <TabPanels>
              <TabPanel>
                <Encode />
              </TabPanel>
              <TabPanel>
                <Decode />
              </TabPanel>
              <TabPanel>
                <CreateKey />
              </TabPanel>
              <TabPanel>
                <ImportKey />
              </TabPanel>
            </TabPanels>
          </Tabs>
        </Box>
      </Box>
    );
  }
};

export default App;
