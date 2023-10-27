import {
  Box,
  Button,
  FormControl,
  FormErrorMessage,
  FormLabel,
  HStack,
  Input,
  NumberDecrementStepper,
  NumberIncrementStepper,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  VStack
} from "@chakra-ui/react";
import { useForm } from "react-hook-form";
import { z } from "zod";

const { api } = window;

const openFileSelectDialog = async () => {
  const path = await api.selectFile(false);
  return path ?? "";
};

const openOutputSelectDialog = async () => {
  const path = await api.selectSaveFile([
    {
      extensions: ["shaa"],
      name: "SHALO AUTH Archive file"
    }
  ]);
  return path ?? "";
};

const prosessEncode = async (va: string) => {
  const result = await api.execJsonMode(va);

  const ParsedStdout = z.object({
    result: z.string(),
    detail: z.string()
  });

  const dialog_message = (() => {
    if (result.stdout === "" && result.err !== null) {
      return "暗号化に失敗しました: " + result.err.message;
    }

    const parsedStdout = ParsedStdout.safeParse(JSON.parse(result.stdout));

    if (parsedStdout.success) {
      if (parsedStdout.data.result === "SHALOA_RESULT_SUCCESS") {
        return "暗号化に成功しました";
      } else {
        return "暗号化に失敗しました: " + parsedStdout.data.detail;
      }
    } else {
      return "暗号化に失敗しました: 実行結果の解析に失敗しました";
    }
  })();

  await api.showMessageDialog({
    type: "info",
    detail: dialog_message,
    message: "",
    noLink: true
  });
};

type EncodeFormValue = {
  inputPath: string;
  outputPath: string;
  keyId: number;
};

const Encode: React.FC = () => {
  const {
    handleSubmit,
    register,
    setValue,
    trigger,
    formState: { errors, isSubmitting, isValid }
  } = useForm<EncodeFormValue>({
    mode: "all"
  });

  const onSubmit = (val: EncodeFormValue) => {
    const params = {
      operation: "Encode",
      properties: {
        inPath: val.inputPath,
        outPath: val.outputPath,
        keyId: Number(val.keyId)
      }
    };

    return prosessEncode(JSON.stringify(params));
  };

  const requiredMessage = "このフィールドは必須です";

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <VStack spacing={8} align="start">
        <Box>
          <FormControl isRequired isInvalid={Boolean(errors.inputPath)}>
            <FormLabel>暗号化するファイル</FormLabel>
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
          <FormControl isRequired isInvalid={Boolean(errors.keyId)}>
            <FormLabel>鍵 ID</FormLabel>
            <NumberInput isRequired defaultValue={1} min={1} max={4}>
              <NumberInputField
                {...register("keyId", {
                  required: requiredMessage
                })}
              />
              <NumberInputStepper>
                <NumberIncrementStepper />
                <NumberDecrementStepper />
              </NumberInputStepper>
            </NumberInput>
            <FormErrorMessage>
              {errors.keyId && errors.keyId.message}
            </FormErrorMessage>
          </FormControl>
        </Box>
        <Box />
      </VStack>
      <Button isDisabled={!isValid} isLoading={isSubmitting} type="submit">
        暗号化
      </Button>
    </form>
  );
};

export default Encode;
