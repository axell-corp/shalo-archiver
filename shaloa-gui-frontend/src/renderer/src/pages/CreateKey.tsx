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

const openOutputSelectDialog = async () => {
  const path = await api.selectSaveFile([
    {
      extensions: ["pem"],
      name: "PEM formatted secret key"
    }
  ]);
  return path ?? "";
};

const prosessCreateKey = async (va: string) => {
  const result = await api.execJsonMode(va);

  const ParsedStdout = z.object({
    result: z.string(),
    detail: z.string()
  });

  const dialog_message = (() => {
    if (result.stdout === "" && result.err !== null) {
      return "鍵生成に失敗しました: " + result.err.message;
    }

    const parsedStdout = ParsedStdout.safeParse(JSON.parse(result.stdout));

    if (parsedStdout.success) {
      if (parsedStdout.data.result === "SHALOA_RESULT_SUCCESS") {
        return "鍵生成に成功しました";
      } else {
        return "鍵生成に失敗しました: " + parsedStdout.data.detail;
      }
    } else {
      return "鍵生成に失敗しました: 実行結果の解析に失敗しました";
    }
  })();

  await api.showMessageDialog({
    type: "info",
    detail: dialog_message,
    message: "",
    noLink: true
  });
};

type CreateKeyFormValue = {
  inputPath: string;
  outputPath: string;
  keyId: number;
};

const CreateKey: React.FC = () => {
  const {
    handleSubmit,
    register,
    setValue,
    trigger,
    formState: { errors, isSubmitting, isValid }
  } = useForm<CreateKeyFormValue>({
    mode: "all"
  });

  const onSubmit = (val: CreateKeyFormValue) => {
    const params = {
      operation: "CreateKey",
      properties: {
        outPath: val.outputPath
      }
    };

    return prosessCreateKey(JSON.stringify(params));
  };

  const requiredMessage = "このフィールドは必須です";

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <VStack spacing={8} align="start">
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
        <Box />
      </VStack>
      <Button isDisabled={!isValid} isLoading={isSubmitting} type="submit">
        生成
      </Button>
    </form>
  );
};

export default CreateKey;
