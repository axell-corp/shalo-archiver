import {
  Box,
  Button,
  FormControl,
  FormErrorMessage,
  FormLabel,
  HStack,
  Input,
  VStack
} from "@chakra-ui/react";
import { useForm } from "react-hook-form";
import { z } from "zod";

const { api } = window;

const openFileSelectDialog = async () => {
  const path = await api.selectFile(true);
  return path ?? "";
};

const openOutputSelectDialog = async () => {
  const path = await api.selectSaveFile();
  return path ?? "";
};

const prosessDecode = async (va: string) => {
  const result = await api.execJsonMode(va);

  const dialog_message = (() => {
    if (result.stdout === "" && result.err !== null) {
      return "復号に失敗しました: " + result.err.message;
    }

    const ParsedStdout = z.object({
      result: z.string(),
      detail: z.string()
    });

    const parsedStdout = ParsedStdout.safeParse(JSON.parse(result.stdout));

    if (parsedStdout.success) {
      if (parsedStdout.data.result === "SHALOA_RESULT_SUCCESS") {
        return "復号に成功しました";
      } else {
        return "復号に失敗しました: " + parsedStdout.data.detail;
      }
    } else {
      return "復号に失敗しました: 実行結果の解析に失敗しました";
    }
  })();

  await api.showMessageDialog({
    type: "info",
    detail: dialog_message,
    message: "",
    noLink: true
  });
};

type DecodeFormValue = {
  inputPath: string;
  outputPath: string;
  pin: string;
};

const Decode: React.FC = () => {
  const {
    handleSubmit,
    register,
    setValue,
    trigger,
    formState: { errors, isSubmitting, isValid }
  } = useForm<DecodeFormValue>({
    mode: "all"
  });

  const onSubmit = (val: DecodeFormValue) => {
    const params = {
      operation: "Decode",
      properties: {
        inPath: val.inputPath,
        outPath: val.outputPath,
        pin: val.pin
      }
    };

    return prosessDecode(JSON.stringify(params));

    //reset();
  };

  const requiredMessage = "このフィールドは必須です";

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <VStack spacing={8} align="start">
        <Box>
          <FormControl isRequired isInvalid={Boolean(errors.inputPath)}>
            <FormLabel>復号するファイル</FormLabel>
            <HStack>
              <Input
                id="inputPath"
                {...register("inputPath", {
                  required: requiredMessage
                })}
              />
              <Button
                onClick={async () => {
                  setValue("inputPath", await openFileSelectDialog());
                  await trigger("inputPath");
                }}
              >
                参照...
              </Button>
            </HStack>
            <FormErrorMessage>
              {errors.inputPath && errors.inputPath.message}
            </FormErrorMessage>
          </FormControl>
        </Box>
        <Box>
          <FormControl isRequired isInvalid={Boolean(errors.outputPath)}>
            <FormLabel>出力先ディレクトリ</FormLabel>
            <HStack>
              <Input
                id="outputPath"
                isInvalid={Boolean(errors.outputPath)}
                {...register("outputPath", {
                  required: requiredMessage
                })}
              />
              <Button
                onClick={async () => {
                  const path = await openOutputSelectDialog();
                  setValue("outputPath", path);
                  await trigger("outputPath");
                }}
              >
                参照...
              </Button>
            </HStack>
            <FormErrorMessage>
              {errors.outputPath && errors.outputPath.message}
            </FormErrorMessage>
          </FormControl>
        </Box>
        <Box>
          <FormControl isRequired isInvalid={Boolean(errors.pin)}>
            <FormLabel>PIN</FormLabel>
            <Input
              type="password"
              {...register("pin", {
                required: requiredMessage
              })}
            />
            <FormErrorMessage>
              {errors.pin && errors.pin.message}
            </FormErrorMessage>
          </FormControl>
        </Box>
        <Box />
      </VStack>
      <Button isDisabled={!isValid} isLoading={isSubmitting} type="submit">
        復号
      </Button>
    </form>
  );
};

export default Decode;
