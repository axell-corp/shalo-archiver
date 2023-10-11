import { Box, Button, FormLabel, Input, VStack, Text } from "@chakra-ui/react";
import { useForm } from "react-hook-form";

const { api } = window;

const processDecode = async (va: string) => {
  const result = await api.autoDecode(va);
  if (result !== "")
    await api.showMessageDialog({
      type: "error",
      detail: result,
      message: "",
      noLink: true
    });
};

type AutoDecodeFormValue = {
  pin: string;
};

const AutoDecode = (props: { filePath: string }) => {
  const {
    handleSubmit,
    register,
    formState: { isSubmitting, isValid }
  } = useForm<AutoDecodeFormValue>({
    mode: "all"
  });

  const onSubmit = (val: AutoDecodeFormValue) => {
    const params = {
      operation: "Decode",
      properties: {
        inPath: props.filePath,
        outPath: "",
        pin: val.pin
      }
    };

    return processDecode(JSON.stringify(params));
  };

  return (
    <>
      <Text>{props.filePath.match(/^.+\\(.+)$/)?.[1]} の復号</Text>
      <form onSubmit={handleSubmit(onSubmit)}>
        <VStack spacing={8} align="start">
          <Box>
            <FormLabel>PIN</FormLabel>
            <Input
              id="pin"
              type="password"
              {...register("pin", {
                required: "必須です"
              })}
            />
          </Box>
          <Box />
        </VStack>
        <Button disabled={!isValid} isLoading={isSubmitting} type="submit">
          復号
        </Button>
      </form>
    </>
  );
};

export default AutoDecode;
