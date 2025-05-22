DIR="Hikari"

if [ -d "$DIR" ]; then
  echo "Directory $DIR exists. Deleting it..."
  rm -rf "$DIR"
  echo "Directory $DIR has been deleted."
else
  echo "Directory $DIR does not exist."
fi

git clone https://github.com/LeadroyaL/llvm-pass-tutorial.git
mv llvm-pass-tutorial/$DIR .
cd $DIR
patch -p1 < ../changes.patch
cd ..
rm -rf llvm-pass-tutorial
