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

const prosessImportKey = async (va: string) => {
  const result = await api.execJsonMode(va);

  const ParsedStdout = z.object({
    result: z.string(),
    detail: z.string()
  });

  const dialog_message = (() => {
    if (result.stdout === "" && result.err !== null) {
      return "インポートに失敗しました: " + result.err.message;
    }

    const parsedStdout = ParsedStdout.safeParse(JSON.parse(result.stdout));

    if (parsedStdout.success) {
      if (parsedStdout.data.result === "SHALOA_RESULT_SUCCESS") {
        return "インポートに成功しました";
      } else {
        return "インポートに失敗しました: " + parsedStdout.data.detail;
      }
    } else {
      return "インポートに失敗しました: 実行結果の解析に失敗しました";
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
  keyId: number;
  subject: string;
  endDate: string;
  pin: string;
};

const ImportKey: React.FC = () => {
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
      operation: "ImportKey",
      properties: {
        inPath: val.inputPath,
        slotId: Number(val.keyId),
        subject: val.subject,
        endDate: val.endDate.replace(/-/g, ""), // yyyy-mm-dd を yyyymmdd にする,
        pin: val.pin
      }
    };
    console.log(params);

    return prosessImportKey(JSON.stringify(params));
  };

  const requiredMessage = "このフィールドは必須です";

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <VStack spacing={8} align="start">
        <Box>
          <FormControl isRequired isInvalid={Boolean(errors.inputPath)}>
            <FormLabel>インポートする鍵ファイル</FormLabel>
            <HStack>
              <Input
                id="outputPath"
                isInvalid={Boolean(errors.inputPath)}
                {...register("inputPath", {
                  required: requiredMessage
                })}
              />
              <Button
                onClick={async () => {
                  const path = await openFileSelectDialog();
                  setValue("inputPath", path);
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
          <FormControl isRequired isInvalid={Boolean(errors.keyId)}>
            <FormLabel>インポート先の鍵 ID</FormLabel>
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
        <Box>
          <FormControl>
            <FormLabel>サブジェクト</FormLabel>
            <Input id="subject" {...register("subject")} />
          </FormControl>
        </Box>
        <Box>
          <FormControl>
            <FormLabel>有効期限</FormLabel>
            <Input
              id="endDate"
              type="date"
              min={new Date().toISOString().split("T")[0]}
              {...register("endDate")}
            />
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
        インポート
      </Button>
    </form>
  );
};

export default ImportKey;
